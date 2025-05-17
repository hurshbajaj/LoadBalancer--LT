use hyper::client::HttpConnector;
use hyper::{Client, Request, Response, Body, Server as HyperServer, Uri};
use hyper::service::{make_service_fn, service_fn};
use tokio::sync::Mutex; 
use tokio::time::timeout;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use anyhow::{self, Context};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json;

static TARGET: Lazy<Mutex<Option<Arc<Mutex<Server>>>>> = Lazy::new(|| Mutex::new(None));
static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(load_from_file("./config.json").unwrap()));
static max_res: Lazy<Mutex<u64>> =  Lazy::new(|| Mutex::new(0u64));

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
    timeout_dur: u64,
    health_check: u64,
    health_check_path: String,
    #[serde(skip)]
    servers: Vec<Arc<Mutex<Server>>>,
}

#[derive(Debug)]
enum ErrorTypes {
    UpstreamServerFailed,
    TimeoutError,
    NoHealthyServerFound,
    HealthCheckFailed,
}

async fn proxy(
    req: Request<Body>,
    client: Arc<Client<HttpConnector>>,
    origin_ip: String,
    timeout_dur: u64,
) -> Result<Response<Body>, anyhow::Error> {

    if let Err(err) = updateTARGET().await{
        return Err(err)
    }

    let guard = TARGET.lock().await; 
    let target_arc = guard.clone().unwrap();
    let mut target = target_arc.lock().await; 

    let new_uri = format!(
        "{}{}",
        target.ip,
        req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/")
    )
    .parse::<Uri>()
    .expect("Failed to parse URI");

    let mut proxied_req = Request::builder()
        .method(req.method())
        .uri(new_uri)
        .version(req.version());

    for (key, value) in req.headers() {
        proxied_req = proxied_req.header(key, value);
    }

    proxied_req = proxied_req.header("X-Forwarded-For", origin_ip);

    let proxied_req = proxied_req
        .body(req.into_body())
        .expect("Failed to build request");

    let start = Instant::now();
    let timeout_result = timeout(Duration::from_secs(timeout_dur), client.request(proxied_req)).await;

    match timeout_result {
        Ok(result) => match result {
            Ok(response) => {
                let mut max = max_res.lock().await;
                if start.elapsed().as_millis() as u64 > *max as u64{
                    *max = start.elapsed().as_millis() as u64;
                }
                target.res_time = ( (start.elapsed().as_millis() as u64) + target.res_time) / 2 as u64;
                Ok(response)
            }
            //this can be intended by the server, dont make it non active
            Err(_) => Err(anyhow::Error::msg(format_error_type(ErrorTypes::UpstreamServerFailed))), 
        },
        Err(_) => {
            if target.strict_timeout{
                target.is_active = false;
            } else{
                target.timeout_tick += 1;
                if target.timeout_tick >= 3{
                    target.is_active = false;
                }
            }
            Err(anyhow::Error::msg(format_error_type(ErrorTypes::TimeoutError)))
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
                println!("weight is {:?}", target.weight);
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
        let mut config = &CONFIG.lock().await;
        let server = config.servers[0].clone();
        *TARGET.lock().await = Some(server);
    }

    let timeout_dur = CONFIG.lock().await.timeout_dur;
    let addr = ([127, 0, 0, 1], 3000).into();
    let client = Arc::new(Client::new());

    let make_svc = make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let remote_addr = conn.remote_addr().to_string();
        let client = client.clone();
        let timeout_dur = timeout_dur.clone();

        async move {
            Ok::<_, anyhow::Error>(service_fn(move |req| {
                let client = client.clone();
                let remote = remote_addr.clone();

                async move {
                    match proxy(req, client, remote, timeout_dur.clone()).await {
                        Ok(response) => Ok::<Response<Body>, anyhow::Error>(response),
                        Err(err) => {
                            println!("Proxy error: {:?}", err);
                            Ok(Response::builder()
                                .status(hyper::StatusCode::BAD_GATEWAY)
                                .body(Body::from(err.to_string()))
                                .unwrap())
                        }
                    }
                }
            }))
        }
    });

    let server = HyperServer::bind(&addr).serve(make_svc);

    println!("Reverse proxy running on http://{}", addr);


    
    let healthCheck = tokio::spawn(async move {
        println!("thread!");
        
        let client = Arc::new(Client::new());
        let config_guard = CONFIG.lock().await;
        let timeout_dur = config_guard.timeout_dur;

        let ip = config_guard.host.clone();

        let uri = format!("http://{}.{}.{}.{}:{}/", ip.0[0], ip.0[1], ip.0[2], ip.0[3], ip.1);

        let servers = config_guard.servers.clone();

        let health_check = config_guard.health_check;

        let health_check_path = config_guard.health_check_path.clone();
        drop(config_guard);

        loop{
            tokio::time::sleep(Duration::from_secs(health_check)).await;
            println!("shud send health chek now");

            let mut Servers = servers.clone();

            for server in Servers{
                health_check_proxy(client.clone(), timeout_dur.clone(), server, health_check_path.clone()).await;
            }

            reorder().await.unwrap();

        }
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
        timeout_dur: u64,
        health_check: u64,
        health_check_path: String,
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
        timeout_dur: raw_config.timeout_dur,
        health_check: raw_config.health_check,
        health_check_path: raw_config.health_check_path,
        servers,
    })
}

async fn updateTARGET() -> anyhow::Result<()> {

    let target_arc = {
        let guard = TARGET.lock().await; 
        guard.clone().unwrap()
    };
    let mut target = target_arc.lock().await;  
    println!("finished mutex locking TARGET");

    let mut config = CONFIG.lock().await;

    println!("config locked");

    let mut at_server_idx = atServerIdx.lock().await;
    println!("server idx locked");

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

    println!("{:?}", at_server_idx); 

    drop(target);

    let mut foundHealthy = false;
    let mut serversChecked = 0;

    while !foundHealthy{

        let server_arc = config.servers[at_server_idx[0] as usize].clone();
        println!("i hate my life");
        let server_guard = server_arc.lock().await;
        let is_active_val = server_guard.is_active.clone();
        println!("YES OMFG");

        if  is_active_val == true{
            println!("No lock");
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

    println!("Healthy server found");

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


//metrics TODO
