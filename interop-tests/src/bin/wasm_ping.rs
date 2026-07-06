#![allow(non_upper_case_globals)]

use std::{future::IntoFuture, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, Uri, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use interop_tests::{BlpopRequest, Report, RpushRequest};
use redis::{AsyncCommands, Client};
use thirtyfour::prelude::*;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
    process::Child,
    sync::mpsc,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod config;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_CHROMEDRIVER_PORT: &str = "45782";

/// Embedded Wasm package
///
/// Make sure to build the wasm with `wasm-pack build --target web`
#[derive(rust_embed::RustEmbed)]
#[folder = "pkg"]
struct WasmPackage;

#[derive(Clone)]
struct TestState {
    redis_client: Client,
    config: config::Config,
    bind_addr: String,
    results_tx: mpsc::Sender<Result<Report, String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // start logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // read env variables
    let mut config = config::Config::from_env()?;
    let test_timeout = Duration::from_secs(config.test_timeout);

    // The browser cannot host the relay a `/webrtc` listener needs, so spawn one in
    // this wrapper process unless an external relay was provided.
    if config.transport == "webrtc" && !config.is_dialer && config.relay_addr.is_none() {
        config.relay_addr = Some(
            interop_tests::relay_server::spawn(&config.ip)
                .await?
                .to_string(),
        );
    }

    // The bind address and chromedriver port are configurable so that two instances,
    // e.g. a `/webrtc` browser listener and browser dialer, can share a host.
    let bind_addr = std::env::var("bind_addr").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_owned());
    let chromedriver_port =
        std::env::var("chromedriver_port").unwrap_or_else(|_| DEFAULT_CHROMEDRIVER_PORT.to_owned());

    // create a redis client
    let redis_client =
        Client::open(config.redis_addr.as_str()).context("Could not connect to redis")?;
    let (results_tx, mut results_rx) = mpsc::channel(1);

    let state = TestState {
        redis_client,
        config,
        bind_addr: bind_addr.clone(),
        results_tx,
    };

    // create a wasm-app service
    let app = Router::new()
        // Redis proxy
        .route("/blpop", post(redis_blpop))
        .route("/rpush", post(redis_rpush))
        // Report tests status
        .route("/results", post(post_results))
        // Wasm ping test trigger
        .route("/", get(serve_index_html))
        // Wasm app static files
        .fallback(serve_wasm_pkg)
        // Middleware
        .layer(CorsLayer::very_permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Run the service in background
    tokio::spawn(axum::serve(TcpListener::bind(&bind_addr).await?, app).into_future());

    // Start executing the test in a browser
    let (mut chrome, driver) = open_in_browser(&bind_addr, &chromedriver_port).await?;

    // Wait for the outcome to be reported
    let test_result = match tokio::time::timeout(test_timeout, results_rx.recv()).await {
        Ok(received) => received.unwrap_or(Err("Results channel closed".to_owned())),
        Err(_) => Err("Test timed out".to_owned()),
    };

    // Close the browser after we got the results
    driver.quit().await?;
    chrome.kill().await?;

    match test_result {
        Ok(report) => println!("{}", serde_json::to_string(&report)?),
        Err(error) => bail!("Tests failed: {error}"),
    }

    Ok(())
}

async fn open_in_browser(bind_addr: &str, chromedriver_port: &str) -> Result<(Child, WebDriver)> {
    // start a webdriver process
    // currently only the chromedriver is supported as firefox doesn't
    // have support yet for the certhashes
    let chromedriver = if cfg!(windows) {
        "chromedriver.cmd"
    } else {
        "chromedriver"
    };
    let mut chrome = tokio::process::Command::new(chromedriver)
        .arg(format!("--port={chromedriver_port}"))
        .stdout(Stdio::piped())
        .spawn()?;
    // read driver's stdout
    let driver_out = chrome
        .stdout
        .take()
        .context("No stdout found for webdriver")?;
    // wait for the 'ready' message
    let mut reader = BufReader::new(driver_out).lines();
    while let Some(line) = reader.next_line().await? {
        if line.contains("ChromeDriver was started successfully") {
            break;
        }
    }

    // run a webdriver client
    let mut caps = DesiredCapabilities::chrome();
    caps.set_headless()?;
    caps.set_disable_dev_shm_usage()?;
    caps.set_no_sandbox()?;
    let driver = WebDriver::new(format!("http://localhost:{chromedriver_port}"), caps).await?;
    // go to the wasm test service
    driver.goto(format!("http://{bind_addr}")).await?;

    Ok((chrome, driver))
}

/// Redis proxy handler.
/// `blpop` is currently the only redis client method used in a ping dialer.
async fn redis_blpop(
    state: State<TestState>,
    request: Json<BlpopRequest>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let client = state.0.redis_client;
    let mut conn = client.get_async_connection().await.map_err(|e| {
        tracing::warn!("Failed to connect to redis: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let res = conn
        .blpop(&request.key, request.timeout as f64)
        .await
        .map_err(|e| {
            tracing::warn!(
                key=%request.key,
                timeout=%request.timeout,
                "Failed to get list elem key within timeout: {e}"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(res))
}

/// Redis proxy handler.
/// `rpush` lets a browser listener publish its advertised multiaddr.
async fn redis_rpush(
    state: State<TestState>,
    request: Json<RpushRequest>,
) -> Result<(), StatusCode> {
    let client = state.0.redis_client;
    let mut conn = client.get_async_connection().await.map_err(|e| {
        tracing::warn!("Failed to connect to redis: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    conn.rpush::<_, _, ()>(&request.key, &request.value)
        .await
        .map_err(|e| {
            tracing::warn!(key=%request.key, "Failed to push list elem: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(())
}

/// Receive test results
async fn post_results(
    state: State<TestState>,
    request: Json<Result<Report, String>>,
) -> Result<(), StatusCode> {
    state.0.results_tx.send(request.0).await.map_err(|_| {
        tracing::error!("Failed to send results");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// Serve the main page which loads our javascript
async fn serve_index_html(state: State<TestState>) -> Result<impl IntoResponse, StatusCode> {
    let bind_addr = state.0.bind_addr;
    let config::Config {
        transport,
        ip,
        is_dialer,
        test_timeout,
        sec_protocol,
        muxer,
        relay_addr,
        ..
    } = state.0.config;

    let sec_protocol = sec_protocol
        .map(|p| format!(r#""{p}""#))
        .unwrap_or("null".to_owned());
    let muxer = muxer
        .map(|p| format!(r#""{p}""#))
        .unwrap_or("null".to_owned());
    let relay_addr = relay_addr
        .map(|a| format!(r#""{a}""#))
        .unwrap_or("null".to_owned());

    Ok(Html(format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8" />
            <title>libp2p ping test</title>
            <script type="module"">
                // import a wasm initialization fn and our test entrypoint
                import init, {{ run_test_wasm }} from "/interop_tests.js";

                // initialize wasm
                await init()
                // run our entrypoint with params from the env
                await run_test_wasm(
                    "{transport}",
                    "{ip}",
                    {is_dialer},
                    {test_timeout}n,
                    "{bind_addr}",
                    {sec_protocol},
                    {muxer},
                    {relay_addr}
                )
            </script>
        </head>

        <body></body>
        </html>
    "#
    )))
}

async fn serve_wasm_pkg(uri: Uri) -> Result<Response, StatusCode> {
    let path = uri.path().trim_start_matches('/').to_string();
    if let Some(content) = WasmPackage::get(&path) {
        let mime = mime_guess::from_path(&path).first_or_octet_stream();
        Ok(Response::builder()
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(content.data.into())
            .unwrap())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
