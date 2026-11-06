//! ssld - SSL certificate lifecycle control plane.
//!
//! No numbered CLI menus: the service is configured through environment
//! variables, `config/ssld.json`, or the settings REST API, and then simply
//! runs. Start it with `cargo run --release` or `./ssld`.
mod access;
mod acme;
mod api;
mod auth;
mod certs;
mod cloud;
mod compat;
mod config;
mod crypto;
mod deploy;
mod dns;
mod error;
mod events;
mod mcp;
mod models;
mod monitor;
mod notify;
mod overview;
mod plugin;
mod private_ca;
mod providers;
mod scheduler;
mod state;
mod store;
mod webhook;
mod workflow;

use config::Config;
use state::Core;
use std::sync::Arc;

fn startup_args() -> (Option<String>, Option<u16>, Option<String>, Option<String>) {
    let mut config = None; let mut port = None; let mut bind = None; let mut data = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => { if i + 1 < args.len() { config = Some(args[i + 1].clone()); i += 1; } }
            "--port" | "-p" => { if i + 1 < args.len() { port = args[i + 1].parse().ok(); i += 1; } }
            "--bind" => { if i + 1 < args.len() { bind = Some(args[i + 1].clone()); i += 1; } }
            "--data-dir" => { if i + 1 < args.len() { data = Some(args[i + 1].clone()); i += 1; } }
            "--version" | "-V" => { println!("ssld {}", env!("CARGO_PKG_VERSION")); std::process::exit(0); }
            "--help" | "-h" => {
                println!("ssld {} - SSL certificate lifecycle control plane\n", env!("CARGO_PKG_VERSION"));
                println!("Usage: ssld [OPTIONS]\n");
                println!("  -c, --config <FILE>   JSON configuration file (default config/ssld.json)");
                println!("  -p, --port <PORT>     Listen port (default 7979)");
                println!("      --bind <ADDR>     Listen address (default 0.0.0.0)");
                println!("      --data-dir <DIR>  State directory (default data)");
                println!("  -V, --version         Print version");
                println!("\nAll other settings come from environment variables or the settings API.");
                println!("There are no service-control commands; stop the process with your process manager.");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    (config, port, bind, data)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .with_target(false).init();

    let (cfg_path, port, bind, data) = startup_args();
    if let Some(p) = cfg_path { std::env::set_var("SSLD_CONFIG", p); }
    if let Some(p) = port { std::env::set_var("SSLD_PORT", p.to_string()); }
    if let Some(b) = bind { std::env::set_var("SSLD_BIND", b); }
    if let Some(d) = data { std::env::set_var("SSLD_DATA_DIR", d); }

    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => { tracing::error!("configuration: {e}"); std::process::exit(1); }
    };
    let address = config.address();
    let https = config.server.https;
    let tls_cert = config.server.tls_cert.clone();
    let tls_key = config.server.tls_key.clone();

    let core: Arc<Core> = match Core::new(config) {
        Ok(c) => c,
        Err(e) => { tracing::error!("startup: {e}"); std::process::exit(1); }
    };
    let _ = core.emit("system.started", "system", serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"), "address": address,
        "mcp_path": core.config.mcp.path, "rest_endpoints": api::ENDPOINT_COUNT,
        "mcp_tools": mcp::TOOL_COUNT
    })).await;

    let _scheduler = scheduler::start(Arc::clone(&core));
    let app = api::router(Arc::clone(&core));
    let listener = match tokio::net::TcpListener::bind(&address).await {
        Ok(l) => l,
        Err(e) => { tracing::error!("cannot bind {address}: {e}"); std::process::exit(1); }
    };

    println!();
    println!("  ssld {}  ·  certificate lifecycle control plane", env!("CARGO_PKG_VERSION"));
    println!("  Console   http://{address}/");
    println!("  REST API  http://{address}/api/v1/health   ({} endpoints)", api::ENDPOINT_COUNT);
    println!("  MCP       http://{address}{}   ({} coarse tools)", core.config.mcp.path, mcp::TOOL_COUNT);
    println!("  Events    http://{address}/api/v1/events/stream");
    println!("  State     {}", core.store.path().display());
    println!();

    if https && !tls_cert.is_empty() && !tls_key.is_empty() {
        match axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls_cert, &tls_key).await {
            Ok(tls) => {
                let addr = address.parse().unwrap_or_else(|_| "0.0.0.0:7979".parse().unwrap());
                if let Err(e) = axum_server::bind_rustls(addr, tls).serve(app.into_make_service()).await {
                    tracing::error!("HTTPS server: {e}");
                }
                return;
            }
            Err(e) => tracing::warn!("HTTPS certificate unavailable ({e}); serving plain HTTP instead"),
        }
    }
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("server: {e}");
    }
}
