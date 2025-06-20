use dashmap::DashMap;
use flate2::{write::{GzDecoder, GzEncoder}, Compression};
use ratatui::crossterm::event::{self, Event, KeyCode};
use sha2::{digest::typenum::Max, Digest, Sha256};
use redis::AsyncCommands;
use url::Url;
use std::{f64::MANTISSA_DIGITS, fs::{self, File}, io::{Cursor, Read, Write}, iter::from_fn, net::{Ipv4Addr, SocketAddrV4, TcpListener}, os::raw, process::Command, str::FromStr, sync::{atomic::{AtomicU16, AtomicU64}, Arc}, thread::{self, current}, time::{Duration, Instant}};
use tokio::{sync::{Mutex, MutexGuard}, time::{self, timeout}};
use hyper::{
    body::to_bytes, client::HttpConnector, header::{HeaderName, HeaderValue}, service::{make_service_fn, service_fn}, Body, Client, Request, Response, Server as HyperServer, Uri
};
use anyhow::{self, Context};
use once_cell::sync::Lazy;
use serde::{de::Error, Deserialize};
use serde_json;
use std::collections::VecDeque;

use futures::future::join_all;
use hyperlocal::{UnixClientExt, UnixConnector, Uri as local_uri};

use std::env;
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use base64::{engine::general_purpose, Engine as _};

use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

mod CLIclient;
use CLIclient::{log};
use regex::Regex;

static TARGET: Lazy<Mutex<Option<Arc<Mutex<Server>>>>> = Lazy::new(|| Mutex::new(None));
static CONFIG_pre: Lazy<Mutex<Result<Config, anyhow::Error>>> = Lazy::new(|| Mutex::new(load_from_file("./config.json")));
static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config::default()));
static max_res: Lazy<Mutex<u64>> =  Lazy::new(|| Mutex::new(1u64));

static max_res_o:  Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));
static max_res_n:  Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));

static atServerIdx: Lazy<Mutex<[u64; 2]>> = Lazy::new(|| Mutex::new([0u64, 0u64]));

static ban_list: Lazy<RwLock<Vec<String>>> = Lazy::new(|| RwLock::new(vec![])); 
#[derive(Deserialize, Clone, Default)]
struct IpStruct([u64; 4], u64);

#[derive(Deserialize, Debug)]
struct Server {
    ip: String,

    #[serde(skip)]
    concurrent: AtomicU64,

    #[serde(skip)]
    weight: u64,
    is_active: bool,

    #[serde(skip)]
    res_time: u64,

    strict_timeout: bool,

    #[serde(skip)]
    timeout_tick: u16,
}

impl PartialEq for Server {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self {
            ip: self.ip.clone(),
            concurrent: AtomicU64::new(self.concurrent.load(Ordering::Relaxed)),
            weight: self.weight,
            is_active: self.is_active,
            res_time: self.res_time,
            strict_timeout: self.strict_timeout,
            timeout_tick: self.timeout_tick,
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            ip: String::default(),

            concurrent: AtomicU64::new(0),

            weight: 0,
            is_active: false,

            res_time: 0,

            strict_timeout: false,

            timeout_tick: 0,
        }
    }
}

#[derive(Deserialize, Clone, Default)]
struct Config {
    host: IpStruct,
    redis_server: u64,
    timeout_dur: u64,
    
    health_check: u64,
    health_check_path: String,
    
    dos_sus_threshhold: u64,
    ddos_cap: u64,
    ddos_grace_factor: f64,
    ban_timeout: u64,

    Method_hash_check: bool, 
    js_challenge: bool,

    dynamic: bool,
    server_spinup_rt_gf: f64, //server spin up restime grace factor

    challenge_url: String,
    Check_out: bool,
    Check_in: bool,
    dtp: f64, //ddos threshold percentile

    #[serde(skip)]
    servers: Vec<Arc<Mutex<Server>>>,
    bin_path: String,
    max_port: u16,
    ipc_path: String,
    ipc: bool,

    min_ua_len: u64,
    blocked_uas: Vec<String>,
    max_concurrent_reqs_ps: u64,
    compression: bool,
    max_cache_mem: String,
    cache_eviction_policy: String,
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
    Suspiscious,
    Load_balance_Verification_Fail,
    BadRequest,
}

use std::sync::atomic::{AtomicU32, Ordering};
type RateLimitMap = Lazy<Arc<DashMap<String, AtomicU32>>>;

static RATE_LIMITS: RateLimitMap = Lazy::new(|| {
    Arc::new(DashMap::new())
});

static MaxConcurrent: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0)); 

static at_port: Lazy<AtomicU16> = Lazy::new(|| AtomicU16::new(0));

fn dos(ip: String){
    let now = Instant::now();

    let mut entry = RATE_LIMITS.entry(ip.clone()).or_insert_with(|| AtomicU32::new(0));

    entry.fetch_add(1, Ordering::SeqCst);

}

struct SlidingQuantile {
    window: VecDeque<u32>,
    max_size: usize,
}

impl SlidingQuantile {
    fn new(size: usize) -> Self {

        let mut deque: VecDeque<u32> = VecDeque::with_capacity(size);
        deque.extend(std::iter::repeat(1).take(size));

        Self { window: deque, max_size: size } // vec![1, 1, 1, 1, ..]
    }

    fn record(&mut self, value: u32) {
        if self.window.len() == self.max_size {
            self.window.pop_front();
        }
        self.window.push_back(value.max(1)); //vec![1, 1, 1, 2]
    }

    fn quantile(&self, q: f64) -> u32 {
        let mut sorted: Vec<u32> = self.window.iter().cloned().collect(); //
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64) * q).floor() as usize;
        sorted.get(idx.min(sorted.len()-1)).cloned().unwrap_or(0)
    }

    async fn is_anomaly(&self, current: u32, threshold: f64, cap: u64, dtp: f64) -> bool {
        let q = self.quantile(dtp).min(cap as u32);
        current as f64 > (q as f64) * threshold
    }
}

async fn proxy(
    mut req: Request<Body>,
    client: client_type,
    origin_ip: String,
    timeout_dur: u64,
    redis_conn: Arc<Mutex<redis::aio::Connection>>,
    dos_threshhold: u64,
) -> Result<Response<Body>, anyhow::Error> {

    CLIclient::total.fetch_add(1, Ordering::SeqCst);

    dos(origin_ip.clone());

   if ban_list.read().await.contains(&origin_ip.clone()){
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::DDoSsus)))
    }

    //no hangup
    //current concurrent fix
    
    let mut check_o = false;
    
    let user_agent = req.headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let Hmac = req.headers()
        .get("X-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let methd = req.method();

    let (min_ua_len, blocked_uas) = {
        let g = CONFIG.lock().await;
        (g.min_ua_len.clone(), g.blocked_uas.clone())
    };
   if user_agent.len() < min_ua_len as usize || blocked_uas.contains(&(user_agent.to_string())) {
        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::InvalidUserAgent)));
    }
    {

        let config_g = CONFIG.lock().await;

        if req.uri().path() == config_g.challenge_url && config_g.js_challenge{
            match serve_js_challenge("/").await {
                Ok(x) => return Ok(x),
                Err(x) => return Err(anyhow::Error::msg(format_error_type(ErrorTypes::Load_balance_Verification_Fail)))
            }
        }

        if config_g.Method_hash_check{
            if config_g.Check_in {
                if !verify_hmac_from_env(methd.to_string().as_str(), Hmac) {
                    return Err(anyhow::Error::msg(format_error_type(ErrorTypes::Suspiscious)));
                }
            }
            if config_g.Check_out {
                check_o = true;
            }
        }
        if !has_js_challenge_cookie(&req) && config_g.js_challenge{
            let redirect_url = format!("{}", config_g.challenge_url);
            return Ok(Response::builder()
                .status(302)
                .header(LOCATION, redirect_url)
                .body(Body::empty())
                .unwrap());
        }
    }

    //hence graph only captures "real" reqs
    let mut count = -1;
    let mut X = CLIclient::reqs.write().await;
    *X += 1u64;
    drop(X);

    let mut cache_req: Request<Body>;
    (cache_req, req) = clone_request(req).await.unwrap();

    let cache_key = build_cache_key(cache_req).await.unwrap();
    
    {
        let mut redis = redis_conn.lock().await;
        match redis.get::<_, Vec<u8>>(&cache_key).await {
            Ok(mut cached_value) => {
                if CONFIG.lock().await.compression{
                    let decompressed = decompress_bytes(&mut cached_value)?;
                    return Ok(Response::new(Body::from(decompressed)))
                }else{
                    return Ok(Response::new(Body::from(cached_value)))
                }
            }
            _ => {}
        }
    }
    

    loop {
        let req_clone: Request<Body>;
        (req_clone, req) = clone_request(req).await.unwrap();

        if let Err(err) = updateTARGET().await {
            return Err(err)
        }

        let guard = TARGET.lock().await;
        let target_arc = guard.clone().unwrap();
        let mut target = target_arc.lock().await;

        let mut proxied_req = Request::builder();

        let (ipc, path) = {
            let g = CONFIG.lock().await;
            (g.ipc.clone(), g.ipc_path.clone())
        };

        if ipc{
            let urii: hyper::Uri = local_uri::new(target.ip.clone(), req_clone.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")).into();
            proxied_req = Request::builder()
                .method(req_clone.method())
                .uri(urii)
                .version(req_clone.version());
        }else{
            let new_uri = format!(
                "{}{}",
                target.ip,
                req_clone.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
            )
                .parse::<Uri>()
                .expect("Failed to parse URI");

            proxied_req = Request::builder()
                .method(req_clone.method())
                .uri(new_uri)
                .version(req_clone.version());
        }

        for (key, value) in req_clone.headers() {
            proxied_req = proxied_req.header(key, value);
        }

        proxied_req = proxied_req.header("X-Forwarded-For", origin_ip.clone());
        if check_o{
            let holdd = methd_hash_from_env(req_clone.method().as_str());
            proxied_req = proxied_req.header("X-secret", holdd.as_str());
        }

        let proxied_req = proxied_req
            .body(req_clone.into_body())
            .expect("Failed to build request");

        let start = Instant::now();

        let mut timeout_result;

        let max_concurrent = {
            let g = CONFIG.lock().await;
            g.max_concurrent_reqs_ps
        };
        if target.concurrent.load(Ordering::SeqCst) >= max_concurrent{continue;}
        target.concurrent.fetch_add(1, Ordering::SeqCst);
        count += 1;

        match client{
            client_type::Http(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(proxied_req)).await;},
            client_type::Ipc(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(proxied_req)).await;},
        }

        target.concurrent.fetch_sub(1, Ordering::SeqCst);

        match timeout_result {
            Ok(result) => match result {
                Ok(mut response) => {
                    // for metrics + weight
                    let mut max = max_res.lock().await;
                    if start.elapsed().as_millis() as u64 > *max as u64 {
                        *max = start.elapsed().as_millis() as u64;
                    }
                    if start.elapsed().as_millis() as u64 > max_res_n.load(Ordering::SeqCst){
                        max_res_n.store(start.elapsed().as_millis() as u64, Ordering::SeqCst);
                    }
                    target.res_time = ((start.elapsed().as_millis() as u64) + target.res_time) / 2 as u64;
                    
                    if count > 0{
                        let mut cg = CONFIG.lock().await;
                        let ci = find_index::<Server>(&cg.servers, &target).await.unwrap();
                        let cn;
                        if ci - 1 < 0{
                            cn = cg.servers.len() - 1;
                        } else{
                            cn = ci-1;
                        }
                        cg.servers[cn].lock().await.is_active == false;
                    }

                    // cache
                    if let Some(cache_control) = response.headers().get("cache-control") {
                        if let Ok(cc_str) = cache_control.to_str() {
                            if let Ok(max_age_secs) = cc_str.parse::<usize>() {
                                if max_age_secs > 0 {
                                    let status = response.status();
                                    let version = response.version();
                                    let headers = response.headers().clone();

                                    let body_bytes = hyper::body::to_bytes(response.into_body()).await?;
                                    let body_string = String::from_utf8(body_bytes.to_vec())?;

                                    let compressed = compress_str(&body_string)?;

                                    let mut redis = redis_conn.lock().await;

                                    let compression_enable = {
                                        CONFIG.lock().await.compression  
                                    };
                                    if compression_enable{
                                       redis.set_ex::<_, _, ()>(&cache_key, compressed, max_age_secs as u64).await.unwrap_or_else(|_|{});
                                    }else{
                                       redis.set_ex::<_, _, ()>(&cache_key, body_string.clone(), max_age_secs as u64).await.unwrap_or_else(|_|{});
                                    }

                                    let mut new_response = Response::builder()
                                        .status(status)
                                        .version(version);

                                    for (k, v) in headers.iter() {
                                        new_response = new_response.header(k, v);
                                    }

                                    let rebuilt = new_response
                                        .body(Body::from(body_string))
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
                        CLIclient::total_bad.fetch_add(1, Ordering::SeqCst);
                        return Err(anyhow::Error::msg(format_error_type(ErrorTypes::BadRequest)))
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
    };
}

async fn find_index<T>(vec: &[Arc<Mutex<T>>], target: &T) -> Option<usize>
where
    T: PartialEq + Send + Sync,
{
    for (i, item) in vec.iter().enumerate() {
        let value = item.lock().await;
        if &(*value) == target {
            return Some(i);
        }
    }
    None
}

async fn health_check_proxy(
    client: client_type,
    timeout_dur: u64,
    server: Arc<Mutex<Server>>,
    health_check_path: String
) -> Result<Response<Body>, anyhow::Error> {

    let target_arc = server.clone();
    let mut target = target_arc.lock().await; 

    let mut req = Request::builder().body(Body::empty()).unwrap();

    let ipc = {
        let g = CONFIG.lock().await;
        g.ipc.clone()
    };

    if ipc{
        let urii: hyper::Uri = local_uri::new(target.ip.clone(), health_check_path.as_str()).into();
        req = Request::builder()
            .method("GET")
            .uri(urii)
            .body(Body::empty())
            .unwrap();
    }else{
        let new_uri = format!(
            "{}{}",
            target.ip,
            health_check_path
            )
            .parse::<Uri>()
            .expect("Failed to parse URI");

        req = Request::builder()
            .method("GET")
            .uri(new_uri)
            .body(Body::empty())
            .unwrap();
    }

    let timeout_result;

    match client{
        client_type::Http(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(req)).await;},
        client_type::Ipc(ref x) => {timeout_result = timeout(Duration::from_secs(timeout_dur), x.request(req)).await;},
    }

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

#[derive(Clone)]
enum client_type{
    Http(Arc<Client<HttpConnector, Body>>),
    Ipc(Arc<Client<UnixConnector, Body>>)
}

use console_subscriber;

#[tokio::main]
async fn main() {
    console_subscriber::init();
    let clientRun = tokio::spawn(async {
        CLIclient::establish().await;
    });
    log("Starting Loadbalancer...");

    if !check_startup().await.is_ok() {
        loop{}
    }

    {
        let config = CONFIG.lock().await;
        let server = config.servers[0].clone();
        *TARGET.lock().await = Some(server);
    }

    let mut config_guard = CONFIG.lock().await;
    let timeout_dur = config_guard.timeout_dur;
    let dos_thresh = config_guard.dos_sus_threshhold;
    let redis_port = config_guard.redis_server;
    config_guard.servers.drain(1..);

    if config_guard.ipc{
        at_port.store(0u16, Ordering::SeqCst);
    }else{
        at_port.store(Url::parse(config_guard.servers[0].lock().await.ip.as_str()).unwrap().port().unwrap() as u16, Ordering::SeqCst);
    }

    let redis_client = redis::Client::open(format!("redis://127.0.0.1:{redis_port}/")).unwrap();
    let con = Arc::new(Mutex::new(redis_client.get_async_connection().await.unwrap()));

    use redis::AsyncCommands;

    {
        let mut conn_guard = con.lock().await;

        let _: () = redis::cmd("CONFIG")
            .arg("SET")
            .arg("maxmemory")
            .arg(config_guard.max_cache_mem.clone().as_str())
            .query_async(&mut *conn_guard).await.unwrap_or_else(|_| {
                elog("Cache Max Memory: Invalid ; Restart Required...");
                loop {}
            });

        let _: () = redis::cmd("CONFIG")
            .arg("SET")
            .arg("maxmemory-policy")
            .arg(config_guard.cache_eviction_policy.as_str())
            .query_async(&mut *conn_guard).await.unwrap_or_else(|_| {
                elog("Cache Eviction Policy: Invalid ; WARNING!");
            });
    }

    let ip_mk = [
        config_guard.host.0[0] as u8,
        config_guard.host.0[1] as u8,
        config_guard.host.0[2] as u8,
        config_guard.host.0[3] as u8,
    ];
    let port_mk = config_guard.host.1 as u16;
    let addr = (ip_mk, port_mk).into();
    let mut client;

    if config_guard.ipc{
        client = client_type::Ipc(Arc::new(Client::unix()));
    }else{
        client = client_type::Http(Arc::new(Client::new()));
    }

    drop(config_guard);

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
                    let st = std::time::Instant::now();
                    match proxy(req, client, remote, timeout_dur.clone(), redis_conn.clone(), thresh.clone()).await {
                        Ok(response) => {
                            let duration = st.elapsed();
                            CLIclient::rt_avg_c.write().await.push(duration.as_millis() as u64);
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

    let ps = tokio::spawn(async {
        let quant = Arc::new(Mutex::new(SlidingQuantile::new(100)));
        let mut last_ban_clear = Instant::now(); // keep track of last ban_list clear time

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let total = RATE_LIMITS.iter().map(|v| v.value().load(Ordering::SeqCst)).sum::<u32>() as u64;
            let qg_arc = Arc::clone(&quant);
            let mut qg = qg_arc.lock().await;
            let mut cg = CONFIG.lock().await;

            if last_ban_clear.elapsed().as_secs() >= cg.ban_timeout {
                ban_list.write().await.clear();
                last_ban_clear = Instant::now();
            }

            if qg.is_anomaly(total as u32, cg.ddos_grace_factor, cg.ddos_cap, cg.dtp).await {
                CLIclient::total_ddos_a.fetch_add(1, Ordering::SeqCst);
                loop {
                    if !check_and_ban_top_ip(cg.dos_sus_threshhold).await {
                        break;
                    }
                }
            } else {
                qg.record(total as u32);
            }

            *(CLIclient::blocked_ips.write().await) = {
                ban_list.read().await.clone()
            };

            if cg.dynamic {
                if !cg.ipc{
                    if max_res_n.load(Ordering::SeqCst) as f64 > max_res_o.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_o.load(Ordering::SeqCst) != 1{
                        'outer: loop{
                            if at_port.load(Ordering::SeqCst) >= cg.max_port {
                                break 'outer;
                            }
                            at_port.fetch_add(1, Ordering::SeqCst);
                            if spawn_server(cg.bin_path.as_str()){
                                let mut NewS = cg.servers.last().unwrap().clone();
                                let mut newS = NewS.lock().await;
                                cg.servers.push(Arc::new(Mutex::new(Server{ip: increment_port(newS.ip.as_str()), weight: 1, is_active: true, res_time: 0, strict_timeout: newS.strict_timeout, timeout_tick: 0, concurrent: AtomicU64::new(0)})));
                                break 'outer;
                            }
                        }
                    }

                    if max_res_o.load(Ordering::SeqCst) as f64 > max_res_n.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_n.load(Ordering::SeqCst) != 1{ 
                        if cg.servers.len() > 1{
                            if kill_server().is_ok() {
                                cg.servers.last().unwrap().lock().await;
                                cg.servers.pop();
                            }
                        }
                    }
                }else{
                    if max_res_n.load(Ordering::SeqCst) as f64 > max_res_o.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_o.load(Ordering::SeqCst) != 1{
                        'outer: loop{
                            if at_port.load(Ordering::SeqCst) >= cg.max_port {
                                break 'outer;
                            }
                            at_port.fetch_add(1, Ordering::SeqCst);
                            if spawn_socket(cg.bin_path.as_str(), cg.ipc_path.as_str()){
                                let mut NewS = cg.servers.last().unwrap().clone();
                                let mut newS = NewS.lock().await;
                                cg.servers.push(Arc::new(Mutex::new(Server{ip: format!("{}", at_port.load(Ordering::SeqCst)), weight: 1, is_active: true, res_time: 0, strict_timeout: newS.strict_timeout, timeout_tick: 0, concurrent: AtomicU64::new(0)})));
                                break 'outer;
                            }
                        }
                    }

                    if max_res_o.load(Ordering::SeqCst) as f64 > max_res_n.load(Ordering::SeqCst) as f64 * cg.server_spinup_rt_gf && max_res_n.load(Ordering::SeqCst) != 1{ 
                        if cg.servers.len() > 1{
                            if kill_socket(cg.ipc_path.as_str()).is_ok() {
                                cg.servers.last().unwrap().lock().await;
                                cg.servers.pop();
                            }
                        }
                    }
                }
            }

            let mut cli_names = CLIclient::server_names.write().await;
            let mut cli_names_p = vec![];
            for s in cg.servers.clone(){
                let to_push = s.lock().await;
                cli_names_p.push(to_push.ip.clone());
            }
            *cli_names = cli_names_p;
            drop(cli_names);

            let mut cli_rts = CLIclient::server_rts.write().await;
            let mut cli_rts_p = vec![];
            for s in cg.servers.clone(){
                let to_push = s.lock().await;
                cli_rts_p.push(to_push.res_time.to_string().clone());
            }
            *cli_rts = cli_rts_p;
            drop(cli_rts);

            let mut cli_ias = CLIclient::server_is_actives.write().await;
            let mut cli_ias_p = vec![];
            for s in cg.servers.clone(){
                let to_push = s.lock().await;
                cli_ias_p.push(to_push.is_active);
            }
            *cli_ias = cli_ias_p;
            drop(cli_ias);
            
            max_res_o.store(max_res_n.load(Ordering::SeqCst), Ordering::SeqCst);
            max_res_n.store(1, Ordering::SeqCst);

            Arc::clone(&RATE_LIMITS).clear();
        }
    });

    let healthCheck = tokio::spawn(async move {

        let (client, timeout_dur, servers, path, health_interval) = {
            let config = CONFIG.lock().await;
            let client;

            if config.ipc{
                client = client_type::Ipc(Arc::new(Client::unix()));
            }else{
                client = client_type::Http(Arc::new(Client::new()));
            }

            (
                client,
                config.timeout_dur,
                config.servers.clone(),
                config.health_check_path.clone(),
                config.health_check,
            )
        };

        log("Health Checks Running...");

        loop {
            tokio::time::sleep(Duration::from_secs(health_interval)).await;

            let mut tasks = vec![];

            for server in servers.clone() {
                let client = client.clone();
                let path = path.clone();
                let srv = server.clone();

                tasks.push(tokio::spawn(async move {
                    health_check_proxy(client, timeout_dur, srv, path).await;
                }));
            }

            for task in tasks {
                let _ = task.await;
            }

            if let Err(e) = reorder().await {
                eprintln!("Failed to reorder servers after health check: {:?}", e);
            }
        }
    });

    log("Load Balancer Running...");
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
        panic!();
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
        ddos_grace_factor: f64,
        ban_timeout: u64,
        servers: Vec<Server>,
        Method_hash_check: bool,
        js_challenge: bool,
        challenge_url: String,
        Check_in: bool,
        Check_out: bool, 
        dynamic: bool,
        server_spinup_rt_gf: f64,
        dtp: f64,
        max_port: u16,
        bin_path: String,

        ipc:bool,
        ipc_path:String,

        min_ua_len: u64,
        blocked_uas: Vec<String>,

        max_concurrent_reqs_ps: u64,

        compression: bool,
        max_cache_mem: String,
        cache_eviction_policy: String,
    }

    let raw_config: RawConfig =
        serde_json::from_str(&json_data).context("Failed to deserialize JSON from file")?;

    log("Loading from config...");

    let servers = raw_config
        .servers
        .into_iter()
        .map(|mut s| {s.weight = 1; Arc::new(Mutex::new(s))})
        .collect();

    Ok(Config {
        host: raw_config.host,
        redis_server: raw_config.redis_server,
        timeout_dur: raw_config.timeout_dur,
        health_check: raw_config.health_check,
        health_check_path: raw_config.health_check_path,
        dos_sus_threshhold: raw_config.dos_sus_threshhold,
        ddos_cap: raw_config.ddos_cap,
        ddos_grace_factor: raw_config.ddos_grace_factor,
        ban_timeout: raw_config.ban_timeout,
        Method_hash_check: raw_config.Method_hash_check,
        js_challenge: raw_config.js_challenge,
        challenge_url: raw_config.challenge_url,
        Check_in: raw_config.Check_in,
        Check_out: raw_config.Check_out,
        servers,
        dtp: raw_config.dtp,
        dynamic: raw_config.dynamic,
        server_spinup_rt_gf: raw_config.server_spinup_rt_gf,
        max_port: raw_config.max_port,
        bin_path: raw_config.bin_path,
        
        ipc: raw_config.ipc,
        ipc_path: raw_config.ipc_path,

        min_ua_len: raw_config.min_ua_len,
        blocked_uas: raw_config.blocked_uas,

        max_concurrent_reqs_ps: raw_config.max_concurrent_reqs_ps,
        compression: raw_config.compression,
        max_cache_mem: raw_config.max_cache_mem,
        cache_eviction_policy: raw_config.cache_eviction_policy,

    })
}
async fn updateTARGET() -> anyhow::Result<()> {
    let (servers, mut at_idx) = {
        let config = CONFIG.lock().await;
        let mut at_server_idx = atServerIdx.lock().await;

        if config.servers.is_empty() {
            return Err(anyhow::anyhow!("No servers available in config."));
        }

        if at_server_idx[1] >= config.servers[at_server_idx[0] as usize].lock().await.weight {
            at_server_idx[1] = 0;
            at_server_idx[0] = (at_server_idx[0] + 1) % config.servers.len() as u64;
        } else {
            at_server_idx[1] += 1;
        }

        (config.servers.clone(), *at_server_idx)
    };

    let mut found_healthy = false;
    let mut checked = 0;
    let mut current_idx = at_idx[0];

    while !found_healthy && checked < servers.len() {
        let server = servers[current_idx as usize].clone();
        {
            let server_guard = server.lock().await;
            if server_guard.is_active {
                found_healthy = true;
            }
        } 

        if found_healthy {
            *TARGET.lock().await = Some(server);
            let mut at_server_idx = atServerIdx.lock().await;
            *at_server_idx = [current_idx, 0];
            return Ok(());
        }

        current_idx = (current_idx + 1) % servers.len() as u64;
        checked += 1;
    }

    Err(anyhow::anyhow!(format_error_type(ErrorTypes::NoHealthyServerFound)))
}

async fn reorder() -> anyhow::Result<()> {
    let servers_snapshot = {
        let config = CONFIG.lock().await;
        config.servers.clone()
    };

    let mut weighted_servers: Vec<(u64, Arc<Mutex<Server>>)> = Vec::new();

    for server_arc in &servers_snapshot {
        let server = server_arc.lock().await;
        let weight = if server.is_active { server.weight } else { 0 };
        weighted_servers.push((weight, server_arc.clone()));
    }

    weighted_servers.sort_by(|a, b| b.0.cmp(&a.0));

    {
        let mut config = CONFIG.lock().await;
        config.servers = weighted_servers.into_iter().map(|(_, srv)| srv).collect();
    }

    let mut idx = atServerIdx.lock().await;
    *idx = [0, 0];

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

pub fn methd_hash_from_env(message: &str) -> String {
    dotenv().ok();
    let secret = match env::var("secret") {
        Ok(val) => val,
        Err(_) => return String::new(),
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap(); 
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let calculated_hash = general_purpose::STANDARD.encode(code_bytes);

    calculated_hash
}

async fn check_and_ban_top_ip(max_per: u64) -> bool {
    let mut entries: Vec<_> = RATE_LIMITS
        .iter()
        .map(|kv| (kv.key().clone(), kv.value().load(Ordering::SeqCst)))
        .collect();

    entries.sort_by(|a, b| b.1.cmp(&a.1));

    // Check the top entry
    if let Some((ip, count)) = entries.first() {
        if *count as u64 > max_per {
            RATE_LIMITS.remove(ip);
            if !ban_list.read().await.contains(ip) {
                ban_list.write().await.push(ip.clone());
            }
            return true;
        }
    }
    false
}

use hyper::header::{SET_COOKIE, LOCATION, COOKIE}; 
use urlencoding;

async fn serve_js_challenge(red: &str) -> Result<Response<Body>, hyper::Error> {
    let html = format!(
        r#"
        <html>
        <head><title>Checking your browser...</title></head>
        <body style="background-color: #0D0E11">
        <script>
          document.cookie = "jschallenge=1; path=/";
          window.location = decodeURIComponent("{}");
        </script>
        <noscript>
          <p>Please enable JavaScript to pass this challenge.</p>
        </noscript>
        </body>
        </html>
        "#,
        red
    );
    Ok(Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(Body::from(html))
        .unwrap())
}

fn has_js_challenge_cookie(req: &Request<Body>) -> bool {
    if let Some(cookie_header) = req.headers().get(COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            return cookie_str.split(';').any(|kv| kv.trim_start().starts_with("jschallenge=1"));
        }
    }
    false
}

fn kill_server() -> anyhow::Result<()> {
    let output = Command::new("lsof")
        .arg("-t")             
        .arg(format!("-i:{}", at_port.load(Ordering::SeqCst) as u16)) 
        .output()?;            

    if output.status.success() {
        let pids = String::from_utf8_lossy(&output.stdout);
        let mut status: Option<std::process::ExitStatus> = None;

        for pid in pids.lines() {
            status = Some(Command::new("kill")
                .arg("-9")        
                .arg(pid)
                .status()?);       
        }
        if status.is_some(){
            if status.unwrap().success(){
                at_port.fetch_sub(1, Ordering::SeqCst);
            }else{
                return Err(anyhow::Error::msg(""));
            }
        }else{
            return Err(anyhow::Error::msg(""));
        }
    }

    Ok(())
}

fn spawn_server(bin_path: &str) -> bool {
    let port = at_port.load(Ordering::SeqCst).to_string();
    let child = Command::new(bin_path)
        .arg("--port")
        .arg(&port)
        .spawn()
        .is_ok();

    child
}

fn increment_port(url_str: &str) -> String {
    let mut url = Url::parse(url_str).unwrap();
    let port = url.port().unwrap();
    url.set_port(Some(port + 1)).unwrap();
    url.to_string()
}

fn spawn_socket(bin_path: &str, spawn_path: &str) -> bool {
    let port = at_port.load(Ordering::SeqCst).to_string();
    let child = Command::new(bin_path)
        .arg("--socket")
        .arg(format!("{}{}.sock", &spawn_path, at_port.load(Ordering::SeqCst)))
        .spawn()
        .is_ok();

    child
}

fn kill_socket(path: &str) -> anyhow::Result<()> {

    fs::remove_file(format!("{}{}.sock", path, at_port.load(Ordering::SeqCst)));
    at_port.fetch_sub(1, Ordering::SeqCst);
    Ok(())
}

static error_token: &'static str = "\x1b[31m[ERROR]\x1b[0m";

fn elog(value: &str) {
    log(error_token);
    log(format!("{value}").as_str());
}

fn glog(value: &str) {
    log(format!("\x1b[92m{value}\x1b[0m").as_str());
}

async fn check_startup() -> anyhow::Result<()> {
    let cg_p_guard = CONFIG_pre.lock().await;
    let mut port;

    if let Ok(config) = &*cg_p_guard {
        let mut cg = CONFIG.lock().await;
        *cg = config.clone(); // clone the inner Config
        port = Some(cg.host.clone());
    } else {
        elog("Failed to load from Config... Restart Needed");
        return Err(anyhow::anyhow!("Failed to load config"))
    }

    let arg = [port.clone().unwrap().0[0] as u8, port.clone().unwrap().0[1] as u8, port.clone().unwrap().0[2] as u8, port.clone().unwrap().0[3] as u8];

    if !check_port(arg, port.clone().unwrap().1 as u16){
        elog("Host Port occupied... Restart Needed");
        return Err(anyhow::anyhow!("Port Occupied"))
    }

    glog("[Startup-Ready]");
    Ok(())
}

fn check_port(addr: [u8; 4], port: u16) -> bool {
    let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let socket = SocketAddrV4::new(ip, port);

    match TcpListener::bind(socket) {
        Ok(listener) => {
            drop(listener); 
            true
        }
        Err(_) => false,
    }
}

fn compress_str(data: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data.as_bytes())?;
    Ok(encoder.finish()?)
}

fn decompress_bytes(data: &mut [u8]) -> Result<String, anyhow::Error> {
    let cursor = Cursor::new(data);
    let mut decoder = GzDecoder::new(cursor);
    let mut decoded = String::new();
    decoder.read_to_string(&mut decoded)?;
    Ok(decoded)
}

pub async fn build_cache_key(mut req: Request<Body>) -> Result<Vec<u8>, anyhow::Error> {
    dotenv::dotenv().ok();

    let method = req.method().clone();
    let uri = req.uri().to_string();

    let whole_body = to_bytes(req.body_mut()).await?;
    *req.body_mut() = Body::from(whole_body.clone());

    let composite = format!(
        "CACHE:{}:{}:{}",
        method,
        uri,
        String::from_utf8_lossy(&whole_body)
    );

    let compress = {
        CONFIG.lock().await.compression
    };

    if !compress{
        return Ok(composite.into_bytes())
    }

    compress_str(&composite)
}

pub fn verify_hmac_from_env(message: &str, provided_hash: &str) -> bool {
    dotenv().ok();
    let secret = match env::var("secret") {
        Ok(val) => val,
        Err(_) => return false,
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let calculated_hash = general_purpose::STANDARD.encode(code_bytes);

    calculated_hash == provided_hash
}
