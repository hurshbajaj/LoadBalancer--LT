use hyper::client::HttpConnector;
use hyper::{Client, Request, Response, Body, Server as HyperServer, Uri};
use hyper::service::{make_service_fn, service_fn};
use tokio::sync::Mutex; 
use tokio::time::timeout;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::{self, Context};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json;

static TARGET: Lazy<Mutex<Option<Arc<Mutex<Server>>>>> = Lazy::new(|| Mutex::new(None));
static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(load_from_file("./config.json").unwrap()));

static atServerIdx: Lazy<Mutex<[u64; 2]>> = Lazy::new(|| Mutex::new([0u64, 0u64]));

#[derive(Deserialize)]
struct IpStruct([u64; 4], u64);

#[derive(Deserialize, Clone)]
struct Server {
    ip: String,
    weight: u64,
    is_active: bool,
    res_time: u64,
}

#[derive(Deserialize)]
struct Config {
    host: IpStruct,
    timeout_dur: u64,
    #[serde(skip)]
    servers: Vec<Arc<Mutex<Server>>>,
}

#[derive(Debug)]
enum ErrorTypes {
    UpstreamServerFailed,
    TimeoutError,
    HealthyServerNotFound,
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
                target.res_time = start.elapsed().as_millis() as u64;
                Ok(response)
            }
            Err(_) => Err(anyhow::Error::msg(format_error_type(ErrorTypes::UpstreamServerFailed))),
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
                //let timeout_dur = timeout_dur.clone();

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
        servers,
    })
}

fn load_from_file_depr(file_path: &str) -> anyhow::Result<Config> {
    let mut file = File::open(file_path).context(format!("Failed to open file: {}", file_path))?;
    let mut json_data = String::new();
    file.read_to_string(&mut json_data).context("Failed to read file")?;
    let deserialized_config: Config =
        serde_json::from_str(&json_data).context("Failed to deserialize JSON from file")?;
    Ok(deserialized_config)
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
    if at_server_idx[1] == target.weight{ //next server needed
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
            return Err(anyhow::Error::msg(format_error_type(ErrorTypes::HealthyServerNotFound)))
        }
    }

    println!("Healthy server found");

    let target_server = config.servers[at_server_idx[0] as usize].clone();
    drop(config);

    *TARGET.lock().await = Some(target_server);

    Ok(())
}

//Nextt => for load_balancer
// 
//make at server: idx static and count static XXX
//in function, which u call before accessing target, XXX
//...
//find active, return err if no XXX
//Handle that err XXX
//make weighted 
//
//health checks
//
//metrics 
