//! Harness self-test for the native to native `/webrtc` matrix cell.
//!
//! Runs the same code paths as the containerized interop test: the listener spawns an
//! in-process relay, reserves a slot on it and advertises a relayed webrtc multiaddr
//! via redis; the dialer picks the multiaddr up, runs the signalling exchange over the
//! relayed connection and pings over the resulting direct connection.
//!
//! Requires a fresh redis instance, e.g.:
//! `docker run --rm -p 6379:6379 redis:7-alpine`
//!
//! Run with: `cargo test -p interop-tests --test webrtc -- --ignored`

#![cfg(not(target_arch = "wasm32"))]

const REDIS_ADDR: &str = "redis://127.0.0.1:6379";

#[tokio::test]
#[ignore = "requires a fresh redis instance on 127.0.0.1:6379"]
async fn native_to_native_webrtc_ping() {
    let relay_addr = interop_tests::relay_server::spawn("127.0.0.1")
        .await
        .expect("relay to spawn");

    // The listener runs until its timeout, so run it in the background and treat the
    // dialer's report as the test outcome.
    let listener = tokio::spawn(interop_tests::run_test(
        "webrtc",
        "127.0.0.1",
        false,
        60,
        REDIS_ADDR,
        None,
        None,
        Some(relay_addr.to_string()),
        None,
    ));

    let report = interop_tests::run_test(
        "webrtc",
        "127.0.0.1",
        true,
        60,
        REDIS_ADDR,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("dialer to ping the listener over the direct connection");

    println!("{}", serde_json::to_string(&report).unwrap());

    listener.abort();
}
