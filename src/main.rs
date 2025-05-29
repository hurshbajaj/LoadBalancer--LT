use dashmap::DashMap;
use sha2::{digest::typenum::Max, Digest, Sha256};
use redis::AsyncCommands;
use std::{fs::File, io::Read, iter::from_fn, str::FromStr, sync::{atomic::AtomicU64, Arc}, thread::{self, current}, time::{Duration, Instant}};
use tokio::{sync::Mutex, time::timeout};
use hyper::{
    body::to_bytes, client::HttpConnector, header::{HeaderName, HeaderValue}, service::{make_service_fn, service_fn}, Body, Client, Request, Response, Server as HyperServer, Uri
};
use anyhow::{self, Context};
use once_cell::sync::Lazy;
use serde::{Deserialize};
use serde_json;

use futures::future::join_all;

mod CLIclient;
mod useragents;
use regex::Regex;

static TARGET: Lazy<Mutex<Option<Arc<Mutex<Server>>>>> = Lazy::new(|| Mutex::new(None));
static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(load_from_file("./config.json").unwrap()));
static max_res: Lazy<Mutex<u64>> =  Lazy::new(|| Mutex::new(1u64));

static atServerIdx: Lazy<Mutex<[u64; 2]>> = Lazy::new(|| Mutex::new([0u64, 0u64]));

#[derive(Deserialize, Clone)]
struct IpStruct([u64; 4], u64);

#[derive(Deserialize, Clone)]
struct Server {
    ip: String,
    weight: u64,
    is_active: bool,
    res_time: u64,

    strict_timeout: bool,
    timeout_tick: u16,
}

#[derive(Deserialize, Clone)]
struct Config {
    host: IpStruct,
    redis_server: u64,
    timeout_dur: u64,
    health_check: u64,
    health_check_path: String,
    dos_sus_threshhold: u64,
    ddos_cap: u64,
    ddos_a: f64,
    ddos_initial_seed: u64,

    #[serde(skip)]
    servers: Vec<Arc<Mutex<Server>>>,
}

#[derive(Debug)]
enum ErrorTypes {
    UpstreamServerFailed,
    TimeoutError,
    NoHealthyServerFound,
    HealthCheckFailed,
    DoSsus,
    DDoSsus,
    InvalidUserAgent,
}

use std::sync::atomic::{AtomicU32, Ordering};
type RateLimitMap = Lazy<Arc<DashMap<String, AtomicU32>>>;

static RATE_LIMITS: RateLimitMap = Lazy::new(|| {
    Arc::new(DashMap::new())
});

static MaxConcurrent: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0)); 

fn dos(ip: String, threshhold: u64) -> bool {
    let now = Instant::now();

    let mut entry = RATE_LIMITS.entry(ip.clone()).or_insert_with(|| AtomicU32::new(0));

    let current_count = entry.load(Ordering::SeqCst);
    if u64::from(current_count) >= threshhold {
        return false;
    }
    entry.fetch_add(1, Ordering::SeqCst);

    true
}

async fn ddos() -> bool {
    //let aa = 0.000000004;

    let mut ret_f = false;
    let cg = CONFIG.lock().await;

    let Concurrent_r = RATE_LIMITS.iter().map(|v| v.value().load(Ordering::SeqCst)).sum::<u32>() as u64;
    let old = MaxConcurrent.load(Ordering::SeqCst);
    let new = (((old as f64) * (1f64- cg.ddos_a) + (Concurrent_r as f64) * cg.ddos_a).ceil() as u64).min(cg.ddos_cap).max(cg.ddos_initial_seed);

    MaxConcurrent.store(new, Ordering::SeqCst); 

    if Concurrent_r > MaxConcurrent.load(Ordering::SeqCst) {
        ret_f = true;
    }

    if ret_f == true{
        return false;
    }
    return true
}

async fn proxy(
    mut req: Request<Body>,
    client: Arc<Client<HttpConnector>>,
    origin_ip: String,
    timeout_dur: u64,
    redis_conn: Arc<Mutex<redis::aio::Connection>>,
    dos_threshhold: u64,
) -> Result<Response<Body>, anyhow::Error> {

    //no hangup
    //current concurrent fix
    if dos(origin_ip.clone(), dos_threshhold) == false {
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::DoSsus)))
    }

    if ddos().await == false{
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::DDoSsus)))
    }

    let user_agent = req.headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !useragents::contains(user_agent) {
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::InvalidUserAgent)));
    }

    let mut count = -1;
    let mut X = CLIclient::reqs.write().await;
    *X += 1u64;
    drop(X);

    let mut cache_req: Request<Body>;
    (cache_req, req) = clone_request(req).await.unwrap();

    let cache_key = build_cache_key(&mut cache_req).await.unwrap();

    {
        let mut redis = redis_conn.lock().await;
        match redis.get::<_, String>(&cache_key).await {
            Ok(cached_value) => {
                // Found in cache, return as response
                return Ok(Response::new(Body::from(cached_value)))
            }
            _ => {}
        }
    }

    loop {
        count += 1;
        let req_clone: Request<Body>;
        (req_clone, req) = clone_request(req).await.unwrap();

        if let Err(err) = updateTARGET().await {
            return Err(err)
        }

        let guard = TARGET.lock().await;
        let target_arc = guard.clone().unwrap();
        let mut target = target_arc.lock().await;

        let new_uri = format!(
            "{}{}",
            target.ip,
            req_clone.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
        )
        .parse::<Uri>()
        .expect("Failed to parse URI");

        let mut proxied_req = Request::builder()
            .method(req_clone.method())
            .uri(new_uri)
            .version(req_clone.version());

        for (key, value) in req_clone.headers() {
            proxied_req = proxied_req.header(key, value);
        }

        proxied_req = proxied_req.header("X-Forwarded-For", origin_ip.clone());

        let proxied_req = proxied_req
            .body(req_clone.into_body())
            .expect("Failed to build request");

        let start = Instant::now();
        let timeout_result = timeout(Duration::from_secs(timeout_dur), client.request(proxied_req)).await;

        match timeout_result {
            Ok(result) => match result {
                Ok(mut response) => {
                    // for metrics + weight
                    let mut max = max_res.lock().await;
                    if start.elapsed().as_millis() as u64 > *max as u64 {
                        *max = start.elapsed().as_millis() as u64;
                    }
                    target.res_time = ((start.elapsed().as_millis() as u64) + target.res_time) / 2 as u64;

                    // cache
                    if let Some(cache_control) = response.headers().get("cache-control") {
                        if let Ok(cc_str) = cache_control.to_str() {
                            if let Ok(max_age_secs) = cc_str.parse::<usize>() {
                                if max_age_secs > 0 {
                                    let status = response.status();
                                    let version = response.version();
                                    let headers = response.headers().clone(); // clone headers

                                    let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
                                    let body_clone_for_cache = body_bytes.clone(); 
                                    let body_clone_for_response = body_bytes.clone();

                                    let body_string = String::from_utf8(body_clone_for_cache.to_vec()).unwrap();

                                    let mut redis = redis_conn.lock().await;
                                    redis.set_ex::<_, _, ()>(&cache_key, body_string, max_age_secs as u64).await?;

                                    // rebuild response
                                    let mut new_response = Response::builder()
                                        .status(status)
                                        .version(version);

                                    for (k, v) in headers.iter() {
                                        new_response = new_response.header(k, v);
                                    }

                                    let rebuilt = new_response
                                        .body(Body::from(body_clone_for_response))
                                        .unwrap();

                                    return Ok(rebuilt);

                                }
                            }
                        }
                    }

                    return Ok(response)
                }
                // this can be intended by the server, don't mark as non-active
                Err(_) => {
                    if count >= 1 {
                        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::UpstreamServerFailed)))
                    }
                }
            },
            Err(_) => {
                if target.strict_timeout {
                    target.is_active = false;
                } else {
                    target.timeout_tick += 1;
                    if target.timeout_tick >= 3 {
                        target.is_active = false;
                    }
                }
                if count >= 1 {
                    return Err(anyhow::Error::msg(format_error_type(ErrorTypes::TimeoutError)))
                }
            }
        }
    }
}

async fn health_check_proxy(
    client: Arc<Client<HttpConnector>>,
    timeout_dur: u64,
    server: Arc<Mutex<Server>>,
    health_check_path: String
) -> Result<Response<Body>, anyhow::Error> {

    let target_arc = server.clone();
    let mut target = target_arc.lock().await; 

    let req = Request::builder().uri(format!("{}{}", target.ip.clone(), health_check_path)).method("GET").body(Body::empty()).unwrap();

    let timeout_result = timeout(Duration::from_secs(timeout_dur), client.request(req)).await;

    match timeout_result {
        Ok(result) => match result {
            Ok(response) => {
                target.is_active = true;
                if *max_res.lock().await != 0{
                    target.weight = ( ( 1-(target.res_time / *(max_res.lock().await) as u64 ) ) * 10 ) as u64;
                }
                Ok(response)
            }
            
            Err(_) => {target.is_active = false; Err(anyhow::Error::msg(format_error_type(ErrorTypes::HealthCheckFailed)))}, 
        },
        Err(_) => {
            
            target.is_active = false;
            Err(anyhow::Error::msg(format_error_type(ErrorTypes::TimeoutError)))
        }
    }
}

#[tokio::main]
async fn main() {

    {
        let config = CONFIG.lock().await;
        let server = config.servers[0].clone();
        *TARGET.lock().await = Some(server);
    }

    let config_guard = CONFIG.lock().await;
    let timeout_dur = config_guard.timeout_dur;
    let dos_thresh = config_guard.dos_sus_threshhold;
    let redis_port = config_guard.redis_server;

    drop(config_guard);

    let redis_client = redis::Client::open(format!("redis://127.0.0.1:{redis_port}/"), ).unwrap(); 
    let con = Arc::new(Mutex::new(redis_client.get_async_connection().await.unwrap()));

    let addr = ([127, 0, 0, 1], 3000).into();
    let client = Arc::new(Client::new());

    let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let remote_addr = conn.remote_addr().to_string();
        let client = client.clone();
        let timeout_dur = timeout_dur.clone();

        let redis_conn = con.clone();
        let thresh = dos_thresh.clone();

        async move {
            Ok::<_, anyhow::Error>(service_fn(move |req| {
                let client = client.clone();
                let remote = remote_addr.clone();

                let redis_conn = redis_conn.clone();
                let thresh = thresh.clone();

                async move {
                    match proxy(req, client, remote, timeout_dur.clone(), redis_conn.clone(), thresh.clone()).await {
                        Ok(response) => {

                            Ok::<_, anyhow::Error>(response)
                        },
                        Err(err) => {
                            Ok(Response::builder()
                                .status(hyper::StatusCode::BAD_GATEWAY)
                                .body(hyper::Body::from(err.to_string()))
                                .unwrap())
                        }
                    }
                }
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);

    let clear_dos = tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Arc::clone(&RATE_LIMITS).clear();
        }
    });

    let healthCheck = tokio::spawn(async move {

        let client = Arc::new(Client::new());
        let config_guard = CONFIG.lock().await;
        let timeout_dur = config_guard.timeout_dur;

        let ip = config_guard.host.clone();

        let uri = format!("http://{}.{}.{}.{}:{}/", ip.0[0], ip.0[1], ip.0[2], ip.0[3], ip.1);

        let servers = config_guard.servers.clone();

        let health_check = config_guard.health_check;

        let health_check_path = config_guard.health_check_path.clone();
        drop(config_guard);

        loop {
            tokio::time::sleep(Duration::from_secs(health_check)).await;

            let mut Servers = servers.clone();

            for server in Servers {
                health_check_proxy(client.clone(), timeout_dur.clone(), server, health_check_path.clone()).await;
            }

            reorder().await.unwrap();

        }
    });

    let clientRun = tokio::spawn(async {
        // cli
        CLIclient::establish().await;
    });

    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}

fn format_error_type(err: ErrorTypes) -> String {
    format!("{:?}", err)
}

fn load_from_file(file_path: &str) -> anyhow::Result<Config> {
    let mut file = File::open(file_path).context(format!("Failed to open file: {}", file_path))?;
    let mut json_data = String::new();
    file.read_to_string(&mut json_data).context("Failed to read file")?;

    #[derive(Deserialize)]
    struct RawConfig {
        host: IpStruct,
        redis_server: u64,
        timeout_dur: u64,
        health_check: u64,
        health_check_path: String,
        dos_sus_threshhold: u64,
        ddos_cap: u64,
        ddos_a: f64,
        ddos_initial_seed: u64,
        servers: Vec<Server>,
    }

    let raw_config: RawConfig =
        serde_json::from_str(&json_data).context("Failed to deserialize JSON from file")?;

    let servers = raw_config
        .servers
        .into_iter()
        .map(|s| Arc::new(Mutex::new(s)))
        .collect();

    Ok(Config {
        host: raw_config.host,
        redis_server: raw_config.redis_server,
        timeout_dur: raw_config.timeout_dur,
        health_check: raw_config.health_check,
        health_check_path: raw_config.health_check_path,
        dos_sus_threshhold: raw_config.dos_sus_threshhold,
        ddos_cap: raw_config.ddos_cap,
        ddos_a: raw_config.ddos_a,
        ddos_initial_seed: raw_config.ddos_initial_seed,
        servers,
    })
}

async fn updateTARGET() -> anyhow::Result<()> {

    let target_arc = {
        let guard = TARGET.lock().await; 
        guard.clone().unwrap()
    };
    let mut target = target_arc.lock().await;  

    let mut config = CONFIG.lock().await;

    let mut at_server_idx = atServerIdx.lock().await;

    //next server IDEALLY
    if at_server_idx[1] >= target.weight{ //next server needed
        at_server_idx[1] = 0;
        if at_server_idx[0] == config.servers.len() as u64 - 1{ //at last server in list
            at_server_idx[0] = 0;
        }else{
            at_server_idx[0] += 1;
        }
    }else{
        at_server_idx[1] += 1;
    }

    drop(target);

    let mut foundHealthy = false;
    let mut serversChecked = 0;

    while !foundHealthy{

        let server_arc = config.servers[at_server_idx[0] as usize].clone();
        let server_guard = server_arc.lock().await;
        let is_active_val = server_guard.is_active.clone();

        if  is_active_val == true{
            foundHealthy = true;
            break;
        }else{
            if at_server_idx[0] == config.servers.len() as u64 - 1{ //at last server in list
                at_server_idx[0] = 0;
            }else{
                at_server_idx[0] += 1;
            }
        }
        serversChecked += 1;
        if serversChecked == config.servers.len() {
            return Err(anyhow::Error::msg(format_error_type(ErrorTypes::NoHealthyServerFound)))
        }
    }

    let target_server = config.servers[at_server_idx[0] as usize].clone();
    drop(config);

    *TARGET.lock().await = Some(target_server);

    Ok(())
}

async fn reorder() -> anyhow::Result<()> {
    let mut config = CONFIG.lock().await;

    let mut weighted_servers: Vec<(u64, Arc<Mutex<Server>>)> = Vec::new();

    for server_arc in &config.servers {
        let server = server_arc.lock().await;
        if server.is_active {
            weighted_servers.push((server.weight, server_arc.clone()));
        } else {
            weighted_servers.push((0, server_arc.clone()));
        }
    }

    weighted_servers.sort_by(|a, b| b.0.cmp(&a.0));

    config.servers = weighted_servers.into_iter().map(|(_, srvr)| srvr).collect();

    drop(config);

    let mut at_server_idx = atServerIdx.lock().await;
    *at_server_idx = [0, 0];

    Ok(())
}

async fn clone_request(req: Request<Body>) -> Result<(Request<Body>, Request<Body>), hyper::Error> {

    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body).await.unwrap();

    let mut req1 = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version.clone())
        .body(Body::from(bytes.clone()))
        .unwrap();

    let mut req2 = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone())
        .version(parts.version.clone())
        .body(Body::from(bytes.clone()))
        .unwrap();

    for (key, value) in parts.headers.clone() {
        let header_name = HeaderName::from_str(key.unwrap().to_string().as_str()).unwrap();
        let header_value = HeaderValue::from_str(value.to_str().unwrap()).unwrap();
        req1.headers_mut().insert(
            header_name.clone(),
            header_value.clone(),
        );
        req2.headers_mut().insert(
            header_name,
            header_value,
        );
    }

    Ok((req1, req2))
} 

pub async fn build_cache_key(req: &mut Request<Body>) -> Result<String, anyhow::Error> {
    let method = req.method().as_str();
    let uri = req.uri().to_string();

    let method = req.method().clone();

    let whole_body = to_bytes(req.body_mut()).await?;
    let body_hash = Sha256::digest(&whole_body);
    let body_digest = hex::encode(body_hash); 

    *req.body_mut() = Body::from(whole_body);

    Ok(format!("CACHE:{}:{}:{}", method, uri, body_digest))
}

