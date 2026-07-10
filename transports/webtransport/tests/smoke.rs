// Copyright 2024 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt, future};
use libp2p_core::{
    Endpoint, Multiaddr, Transport,
    multiaddr::Protocol,
    muxing::{StreamMuxerBox, StreamMuxerExt},
    transport::{Boxed, DialOpts, ListenerId, PortUse, TransportEvent},
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_webtransport as webtransport;
use time::{OffsetDateTime, ext::NumericalDuration};
use tracing_subscriber::EnvFilter;

/// Single-certificate transport (exercises the back-compat `Config::new` path).
fn create_transport() -> (PeerId, Boxed<(PeerId, StreamMuxerBox)>) {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    // A certificate valid since yesterday so that the validity window is already open.
    let not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
    let cert = webtransport::Certificate::generate(not_before).expect("generate cert");

    let config = webtransport::Config::new(&keypair, cert);
    let transport = webtransport::Transport::new(config)
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed();

    (peer_id, transport)
}

/// Two-certificate (current + next) transport built via `Config::generate`.
fn create_transport_generate() -> (PeerId, Boxed<(PeerId, StreamMuxerBox)>) {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let config = webtransport::Config::generate(&keypair, OffsetDateTime::now_utc())
        .expect("generate certs");
    let transport = webtransport::Transport::new(config)
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed();

    (peer_id, transport)
}

async fn start_listening(transport: &mut Boxed<(PeerId, StreamMuxerBox)>, addr: &str) -> Multiaddr {
    transport
        .listen_on(ListenerId::next(), addr.parse().unwrap())
        .unwrap();

    match transport.select_next_some().await {
        TransportEvent::NewAddress { listen_addr, .. } => listen_addr,
        e => panic!("Unexpected event: {e:?}"),
    }
}

/// Drive a listener+dialer ping-pong over `dial_addr`, returning the peer ids each side observed.
///
/// The listener accepts one connection and echoes `PING` -> `PONG` on the first inbound stream;
/// the dialer opens an outbound stream, sends `PING`, and expects `PONG`. Both sides bubble up
/// dial/handshake errors via the returned `Result` so negative tests can assert clean failures.
async fn run_ping_pong(
    mut listener: Boxed<(PeerId, StreamMuxerBox)>,
    mut dialer: Boxed<(PeerId, StreamMuxerBox)>,
    dial_addr: Multiaddr,
) -> Result<(PeerId, PeerId), String> {
    let listener_task = async move {
        loop {
            if let TransportEvent::Incoming { upgrade, .. } = listener.select_next_some().await {
                let (remote_peer, mut conn) = upgrade.await.map_err(|e| e.to_string())?;

                let mut stream = future::poll_fn(|cx| {
                    let _ = conn.poll_unpin(cx)?;
                    conn.poll_inbound_unpin(cx)
                })
                .await
                .map_err(|e| e.to_string())?;

                let mut buf = [0u8; 4];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| e.to_string())?;
                assert_eq!(&buf, b"PING");
                stream.write_all(b"PONG").await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
                // Keep the connection alive briefly so the dialer can read the response.
                libp2p_timer::Delay::new(Duration::from_secs(1)).await;

                return Ok::<PeerId, String>(remote_peer);
            }
        }
    };

    let dialer_task = async move {
        let (remote_peer, mut conn) = dialer
            .dial(
                dial_addr,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                },
            )
            .map_err(|e| format!("{e:?}"))?
            .await
            .map_err(|e| e.to_string())?;

        let mut stream = future::poll_fn(|cx| {
            let _ = conn.poll_unpin(cx)?;
            conn.poll_outbound_unpin(cx)
        })
        .await
        .map_err(|e| e.to_string())?;

        stream.write_all(b"PING").await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(&buf, b"PONG");

        Ok::<PeerId, String>(remote_peer)
    };

    // Race the two tasks. On a successful dial both complete; on a failed dial only the dialer
    // completes (the listener never sees an inbound connection), so we must not block on the
    // listener in that case.
    futures::pin_mut!(listener_task);
    futures::pin_mut!(dialer_task);
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        match future::select(listener_task, dialer_task).await {
            // Listener finished first (success): await the dialer too.
            future::Either::Left((listener_out, dialer_fut)) => {
                let dialer_out = dialer_fut.await;
                (Some(listener_out), dialer_out)
            }
            // Dialer finished first: if it failed, return immediately; if it succeeded, await the
            // listener for its observed peer id.
            future::Either::Right((dialer_out, listener_fut)) => match dialer_out {
                Ok(peer) => (Some(listener_fut.await), Ok(peer)),
                Err(e) => (None, Err(e)),
            },
        }
    })
    .await
    .map_err(|_| "test timed out".to_string())?;

    let (listener_out, dialer_out) = outcome;
    let remote_on_dialer = dialer_out?;
    let remote_on_listener = listener_out.expect("listener ran on success")?;
    Ok((remote_on_listener, remote_on_dialer))
}

/// A native WebTransport node dials another native WebTransport node, the Noise handshake
/// authenticates both peers, and a bidirectional stream opened by the dialer is echoed back by
/// the listener.
#[tokio::test]
async fn native_to_native_ping_pong() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (listener_peer_id, mut listener) = create_transport();
    let (dialer_peer_id, dialer) = create_transport();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    // The listen address already carries the `/certhash`; append the expected peer id.
    let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

    let (remote_on_listener, remote_on_dialer) = run_ping_pong(listener, dialer, dial_addr)
        .await
        .expect("ping-pong succeeds");

    // Each side authenticated the other's libp2p identity via the Noise handshake.
    assert_eq!(remote_on_listener, dialer_peer_id);
    assert_eq!(remote_on_dialer, listener_peer_id);
}

/// A single-certificate transport whose `Config` has been tuned via the chained setters,
/// including disabling path-MTU discovery.
fn create_transport_custom_config() -> (PeerId, Boxed<(PeerId, StreamMuxerBox)>) {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
    let cert = webtransport::Certificate::generate(not_before).expect("generate cert");

    let config = webtransport::Config::new(&keypair, cert)
        .max_idle_timeout(20_000)
        .keep_alive_interval(Duration::from_secs(3))
        .max_concurrent_stream_limit(64)
        .max_stream_data(1_000_000)
        .max_connection_data(2_000_000)
        .handshake_timeout(Duration::from_secs(10))
        .disable_path_mtu_discovery();

    let transport = webtransport::Transport::new(config)
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed();
    (peer_id, transport)
}

/// A single-certificate transport whose certificate was round-tripped through
/// `to_bytes`/`parse` (i.e. persisted and restored), exercising the stabilized serialization.
fn create_transport_from_serialized_cert() -> (PeerId, Boxed<(PeerId, StreamMuxerBox)>) {
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
    let cert = webtransport::Certificate::generate(not_before).expect("generate cert");

    // Persist and restore the certificate via the versioned serialization format.
    let bytes = cert.to_bytes();
    let restored = webtransport::Certificate::parse(&bytes).expect("parse round-trips");

    let config = webtransport::Config::new(&keypair, restored);
    let transport = webtransport::Transport::new(config)
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed();
    (peer_id, transport)
}

/// A native node whose `Config` was tuned via the public setters (and with path-MTU discovery
/// disabled) still completes the handshake and a stream echo.
#[tokio::test]
async fn native_to_native_with_custom_config() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (listener_peer_id, mut listener) = create_transport_custom_config();
    let (dialer_peer_id, dialer) = create_transport_custom_config();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

    let (remote_on_listener, remote_on_dialer) = run_ping_pong(listener, dialer, dial_addr)
        .await
        .expect("custom-config ping-pong succeeds");

    assert_eq!(remote_on_listener, dialer_peer_id);
    assert_eq!(remote_on_dialer, listener_peer_id);
}

/// A listener whose certificate was persisted (`to_bytes`) and restored (`parse`) serves the same
/// pinned `/certhash`, so a dialer connects and echoes successfully.
#[tokio::test]
async fn native_to_native_with_serialized_cert() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (listener_peer_id, mut listener) = create_transport_from_serialized_cert();
    let (dialer_peer_id, dialer) = create_transport();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

    let (remote_on_listener, remote_on_dialer) = run_ping_pong(listener, dialer, dial_addr)
        .await
        .expect("serialized-cert ping-pong succeeds");

    assert_eq!(remote_on_listener, dialer_peer_id);
    assert_eq!(remote_on_dialer, listener_peer_id);
}

// B9: after the dialer closes its *send* (write) half, it must still read a full reply the
// listener writes. Pre-fix, `poll_read` consulted the send-half close state and fabricated a clean
// EOF (`Ok(0)`), truncating the read. This exercises the reachable path: a local `close()` of the
// writer must not affect the recv half.
#[tokio::test]
async fn native_half_closed_read_after_send_close() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    const REPLY_LEN: usize = 4096;

    let (listener_peer_id, mut listener) = create_transport();
    let (_, mut dialer) = create_transport();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

    let listener_task = async move {
        loop {
            if let TransportEvent::Incoming { upgrade, .. } = listener.select_next_some().await {
                let (_remote, mut conn) = upgrade.await.map_err(|e| e.to_string())?;
                let mut stream = future::poll_fn(|cx| {
                    let _ = conn.poll_unpin(cx)?;
                    conn.poll_inbound_unpin(cx)
                })
                .await
                .map_err(|e| e.to_string())?;

                // Read the dialer's PING, then send a large reply *after* the dialer has closed its
                // writer. Keep the connection alive so the dialer can drain it.
                let mut buf = [0u8; 4];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| e.to_string())?;
                assert_eq!(&buf, b"PING");
                let reply = vec![0xABu8; REPLY_LEN];
                stream.write_all(&reply).await.map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
                // Close our writer too so the dialer eventually observes a genuine recv FIN.
                stream.close().await.map_err(|e| e.to_string())?;
                libp2p_timer::Delay::new(Duration::from_secs(2)).await;
                return Ok::<(), String>(());
            }
        }
    };

    let dialer_task = async move {
        let (_remote, mut conn) = dialer
            .dial(
                dial_addr,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                },
            )
            .map_err(|e| format!("{e:?}"))?
            .await
            .map_err(|e| e.to_string())?;

        let mut stream = future::poll_fn(|cx| {
            let _ = conn.poll_unpin(cx)?;
            conn.poll_outbound_unpin(cx)
        })
        .await
        .map_err(|e| e.to_string())?;

        stream.write_all(b"PING").await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        // Close the *send* half. Reads must remain unaffected.
        stream.close().await.map_err(|e| e.to_string())?;

        // A write after close must error (the send half really is closed).
        assert!(
            stream.write_all(b"X").await.is_err(),
            "write after close must fail"
        );

        // The full 4 KiB reply must still be readable despite the closed send half.
        let mut reply = vec![0u8; REPLY_LEN];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|e| format!("read after send-close failed: {e}"))?;
        assert!(reply.iter().all(|&b| b == 0xAB), "reply payload intact");

        // After draining + the peer's FIN, the next read is a genuine recv EOF (Ok(0)), sourced
        // from quinn's recv half, not from the send-close state.
        let mut tail = [0u8; 1];
        let n = stream.read(&mut tail).await.map_err(|e| e.to_string())?;
        assert_eq!(n, 0, "expected genuine recv FIN after draining");

        Ok::<(), String>(())
    };

    futures::pin_mut!(listener_task);
    futures::pin_mut!(dialer_task);
    let (l, d) = tokio::time::timeout(Duration::from_secs(30), async {
        futures::future::join(listener_task, dialer_task).await
    })
    .await
    .expect("test timed out");
    l.expect("listener side");
    d.expect("dialer side");
}

// B9: a recv-half reset surfaces as an `Err`, not a clean EOF. The listener resets/drops its stream
// without a clean FIN; the dialer's `read_exact` of a never-arriving payload must error.
#[tokio::test]
async fn native_recv_reset_is_error() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let (listener_peer_id, mut listener) = create_transport();
    let (_, mut dialer) = create_transport();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

    let listener_task = async move {
        loop {
            if let TransportEvent::Incoming { upgrade, .. } = listener.select_next_some().await {
                let (_remote, mut conn) = upgrade.await.map_err(|e| e.to_string())?;
                let mut stream = future::poll_fn(|cx| {
                    let _ = conn.poll_unpin(cx)?;
                    conn.poll_inbound_unpin(cx)
                })
                .await
                .map_err(|e| e.to_string())?;

                // Read the PING, then abruptly close the whole connection without a clean stream
                // FIN, so the dialer sees a reset rather than EOF.
                let mut buf = [0u8; 4];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| e.to_string())?;
                drop(stream);
                future::poll_fn(|cx| conn.poll_close_unpin(cx))
                    .await
                    .map_err(|e| e.to_string())?;
                return Ok::<(), String>(());
            }
        }
    };

    let dialer_task = async move {
        let (_remote, mut conn) = dialer
            .dial(
                dial_addr,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                },
            )
            .map_err(|e| format!("{e:?}"))?
            .await
            .map_err(|e| e.to_string())?;

        let mut stream = future::poll_fn(|cx| {
            let _ = conn.poll_unpin(cx)?;
            conn.poll_outbound_unpin(cx)
        })
        .await
        .map_err(|e| e.to_string())?;

        stream.write_all(b"PING").await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        // The listener resets the connection; a read of a never-arriving 4-byte reply must error,
        // not return a clean EOF.
        let mut buf = [0u8; 4];
        let res = stream.read_exact(&mut buf).await;
        assert!(res.is_err(), "recv reset must surface as Err, got {res:?}");
        Ok::<(), String>(())
    };

    futures::pin_mut!(listener_task);
    futures::pin_mut!(dialer_task);
    let (_l, d) = tokio::time::timeout(Duration::from_secs(30), async {
        futures::future::join(listener_task, dialer_task).await
    })
    .await
    .expect("test timed out");
    d.expect("dialer side");
}

/// Extract the `/certhash` components from a listen multiaddr.
fn certhashes(addr: &Multiaddr) -> Vec<Protocol<'static>> {
    addr.iter()
        .filter_map(|p| match p {
            Protocol::Certhash(_) => Some(p.acquire()),
            _ => None,
        })
        .collect()
}

/// Rebuild a dial multiaddr keeping the base (ip/udp/quic-v1/webtransport) but replacing the
/// certhash set with `hashes`, then appending the listener peer id.
fn dial_addr_with(
    listen_addr: &Multiaddr,
    hashes: &[Protocol<'static>],
    peer: PeerId,
) -> Multiaddr {
    let mut out = Multiaddr::empty();
    for p in listen_addr.iter() {
        if !matches!(p, Protocol::Certhash(_)) {
            out.push(p.acquire());
        }
    }
    for h in hashes {
        out.push(h.clone());
    }
    out.with(Protocol::P2p(peer))
}

/// I1: ping-pong succeeds when the listener is built with `Config::generate` (current+next pair).
#[tokio::test]
async fn generate_config_ping_pong() {
    let (listener_peer_id, mut listener) = create_transport_generate();
    let (dialer_peer_id, dialer) = create_transport_generate();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    assert_eq!(
        certhashes(&listen_addr).len(),
        2,
        "two advertised certhashes"
    );
    let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

    let (remote_on_listener, remote_on_dialer) = run_ping_pong(listener, dialer, dial_addr)
        .await
        .expect("ping-pong succeeds");
    assert_eq!(remote_on_listener, dialer_peer_id);
    assert_eq!(remote_on_dialer, listener_peer_id);
}

/// I2: a dialer pinning ONLY the active (current) certhash still connects (`{active} ⊆ Noise`).
#[tokio::test]
async fn dial_pinning_only_active_hash() {
    let (listener_peer_id, mut listener) = create_transport_generate();
    let (_, dialer) = create_transport_generate();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    let hashes = certhashes(&listen_addr);
    // `cert_hashes()` is active-first; the multiaddr emits them last-element-first, so the *last*
    // certhash in the address is the active (current) one.
    let active = hashes.last().cloned().expect("at least one certhash");
    let dial_addr = dial_addr_with(&listen_addr, &[active], listener_peer_id);

    run_ping_pong(listener, dialer, dial_addr)
        .await
        .expect("dial pinning only the active hash succeeds");
}

/// I3: a dialer pinning BOTH advertised certhashes connects (the browser `serverCertificateHashes`
/// path). Pinning only the *next* (advertised-but-not-yet-served) hash cannot succeed before
/// rotation, because TLS pins the *served* certificate — so this asserts the supported two-hash
/// case and that the order of the two `/certhash` components is not load-bearing.
#[tokio::test]
async fn dial_pinning_both_hashes_reversed_order() {
    let (listener_peer_id, mut listener) = create_transport_generate();
    let (_, dialer) = create_transport_generate();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    let mut hashes = certhashes(&listen_addr);
    hashes.reverse(); // order must not matter to the dialer
    let dial_addr = dial_addr_with(&listen_addr, &hashes, listener_peer_id);

    run_ping_pong(listener, dialer, dial_addr)
        .await
        .expect("dial pinning both hashes (reversed order) succeeds");
}

/// The advertised-but-not-served `next` certificate cannot be pinned alone before rotation: TLS
/// pins the served (current) certificate, so a dialer offering only the `next` hash is rejected
/// cleanly (no hang/panic). This documents the served-vs-advertised distinction.
#[tokio::test]
async fn dial_pinning_only_next_hash_fails_cleanly() {
    let (listener_peer_id, mut listener) = create_transport_generate();
    let (_, dialer) = create_transport_generate();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    let hashes = certhashes(&listen_addr);
    // The first certhash in the rendered address is the `next` certificate (not currently served).
    let next = hashes.first().cloned().expect("two certhashes");
    let dial_addr = dial_addr_with(&listen_addr, &[next], listener_peer_id);

    let result = run_ping_pong(listener, dialer, dial_addr).await;
    assert!(
        result.is_err(),
        "pinning only the non-served next hash must fail, got {result:?}"
    );
}

/// I5: a dialer pinning an unadvertised (stale) certhash fails cleanly — no hang, no panic.
#[tokio::test]
async fn dial_stale_hash_fails_cleanly() {
    let (listener_peer_id, mut listener) = create_transport_generate();
    let (_, dialer) = create_transport_generate();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;

    // Mint a certificate the listener never advertised and pin only its hash.
    let stale = webtransport::Certificate::generate(OffsetDateTime::now_utc()).expect("stale cert");
    let stale_hash = Protocol::Certhash(stale.cert_hash());
    let dial_addr = dial_addr_with(&listen_addr, &[stale_hash], listener_peer_id);

    let result = run_ping_pong(listener, dialer, dial_addr).await;
    assert!(
        result.is_err(),
        "dial with an unadvertised certhash must fail, got {result:?}"
    );
}
