use anyhow::Result;

mod config;

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::Config::from_env()?;

    // A `/webrtc` listener must be reachable through a relay: spawn an in-process one
    // unless an external relay was provided.
    let relay_addr = match (&*config.transport, config.is_dialer, config.relay_addr) {
        ("webrtc", false, None) => Some(
            interop_tests::relay_server::spawn(&config.ip)
                .await?
                .to_string(),
        ),
        (_, _, relay_addr) => relay_addr,
    };

    let report = interop_tests::run_test(
        &config.transport,
        &config.ip,
        config.is_dialer,
        config.test_timeout,
        &config.redis_addr,
        config.sec_protocol,
        config.muxer,
        relay_addr,
        config.ice_server,
    )
    .await?;

    println!("{}", serde_json::to_string(&report)?);

    Ok(())
}
