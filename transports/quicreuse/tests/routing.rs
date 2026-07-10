// Copyright 2026 Protocol Labs.
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

use std::{sync::Arc, time::Duration};

use futures::{StreamExt, channel::mpsc};
use libp2p_identity::Keypair;
use libp2p_quicreuse::{Error, SharedQuicEndpoint};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

const LIBP2P: &[u8] = b"libp2p";
const H3: &[u8] = b"h3";
const FALLBACK: &[u8] = b"fallback";
const TIMEOUT: Duration = Duration::from_secs(10);

/// A `ServerConfig` enforcing the given ALPN allowlist. The routing key it is registered under
/// is separate: the allowlist is what the handshake enforces, whatever the peek said.
fn server_config(keypair: &Keypair, allowlist: &[&[u8]]) -> Arc<quinn::ServerConfig> {
    let mut tls = libp2p_tls::make_server_config(keypair).unwrap();
    tls.alpn_protocols = allowlist.iter().map(|a| a.to_vec()).collect();
    Arc::new(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).unwrap(),
    )))
}

fn client_config(keypair: &Keypair, alpn_protocols: &[&[u8]]) -> quinn::ClientConfig {
    let mut tls = libp2p_tls::make_client_config(keypair, None).unwrap();
    tls.alpn_protocols = alpn_protocols.iter().map(|a| a.to_vec()).collect();
    quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()))
}

fn endpoint() -> SharedQuicEndpoint {
    SharedQuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap()
}

async fn recv(rx: &mut mpsc::Receiver<quinn::Connecting>) -> quinn::Connecting {
    tokio::time::timeout(TIMEOUT, rx.next())
        .await
        .expect("timed out waiting for routed connection")
        .expect("sink closed")
}

/// The server rejects an ALPN mismatch with a TLS `no_application_protocol` alert, which the
/// client observes as a connection close carrying the corresponding crypto error code.
fn assert_alpn_mismatch(err: &quinn::ConnectionError) {
    match err {
        quinn::ConnectionError::ConnectionClosed(close) => {
            assert_eq!(
                close.error_code,
                quinn::TransportErrorCode::crypto(0x78),
                "unexpected close: {close:?}"
            );
        }
        other => panic!("expected ALPN-mismatch close, got: {other:?}"),
    }
}

fn negotiated_alpn(connection: &quinn::Connection) -> Vec<u8> {
    connection
        .handshake_data()
        .unwrap()
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .unwrap()
        .protocol
        .unwrap()
}

/// Both registered ALPNs route to their own sink and complete their handshakes.
#[tokio::test]
async fn routes_by_offered_alpn() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (libp2p_tx, mut libp2p_rx) = mpsc::channel(8);
    let (h3_tx, mut h3_rx) = mpsc::channel(8);
    listener
        .register(
            LIBP2P.to_vec(),
            server_config(&keypair, &[LIBP2P]),
            libp2p_tx,
        )
        .unwrap();
    // Promotion: a second ALPN on the same socket.
    listener
        .register(H3.to_vec(), server_config(&keypair, &[H3]), h3_tx)
        .unwrap();

    let dialer = endpoint();

    let outbound_h3 = dialer
        .dial_quic(listener.local_addr(), client_config(&keypair, &[H3]), "l")
        .unwrap();
    let inbound_h3 = recv(&mut h3_rx).await;
    let (outbound, inbound) = tokio::join!(outbound_h3, inbound_h3);
    let (outbound, inbound) = (outbound.unwrap(), inbound.unwrap());
    assert_eq!(negotiated_alpn(&outbound), H3);
    assert_eq!(negotiated_alpn(&inbound), H3);

    let outbound_libp2p = dialer
        .dial_quic(
            listener.local_addr(),
            client_config(&keypair, &[LIBP2P]),
            "l",
        )
        .unwrap();
    let inbound_libp2p = recv(&mut libp2p_rx).await;
    let (outbound, inbound) = tokio::join!(outbound_libp2p, inbound_libp2p);
    let (outbound, inbound) = (outbound.unwrap(), inbound.unwrap());
    assert_eq!(negotiated_alpn(&outbound), LIBP2P);
    assert_eq!(negotiated_alpn(&inbound), LIBP2P);

    // Nothing leaked to the other sink.
    assert!(libp2p_rx.try_next().is_err());
    assert!(h3_rx.try_next().is_err());
}

/// An offered ALPN matching no registered route is accepted with the default
/// (first-registered) config and delivered on the default sink.
#[tokio::test]
async fn unknown_alpn_routes_to_default() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (libp2p_tx, mut libp2p_rx) = mpsc::channel(8);
    let (h3_tx, mut h3_rx) = mpsc::channel(8);
    // The default config's allowlist also permits FALLBACK so the handshake can complete
    // and delivery is observable; FALLBACK itself is not a registered route.
    listener
        .register(
            LIBP2P.to_vec(),
            server_config(&keypair, &[LIBP2P, FALLBACK]),
            libp2p_tx,
        )
        .unwrap();
    listener
        .register(H3.to_vec(), server_config(&keypair, &[H3]), h3_tx)
        .unwrap();

    let dialer = endpoint();
    let outbound = dialer
        .dial_quic(
            listener.local_addr(),
            client_config(&keypair, &[FALLBACK]),
            "l",
        )
        .unwrap();

    let inbound = recv(&mut libp2p_rx).await;
    let (outbound, inbound) = tokio::join!(outbound, inbound);
    let (outbound, inbound) = (outbound.unwrap(), inbound.unwrap());
    assert_eq!(negotiated_alpn(&outbound), FALLBACK);
    assert_eq!(negotiated_alpn(&inbound), FALLBACK);
    assert!(h3_rx.try_next().is_err());
}

/// An unknown offered ALPN falls back to the default config, whose allowlist then rejects
/// the handshake: the peek can misroute but never mis-authenticate.
#[tokio::test]
async fn unknown_alpn_is_rejected_by_default_config() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (libp2p_tx, mut libp2p_rx) = mpsc::channel(8);
    let (h3_tx, mut h3_rx) = mpsc::channel(8);
    listener
        .register(
            LIBP2P.to_vec(),
            server_config(&keypair, &[LIBP2P]),
            libp2p_tx,
        )
        .unwrap();
    listener
        .register(H3.to_vec(), server_config(&keypair, &[H3]), h3_tx)
        .unwrap();

    let dialer = endpoint();
    let outbound = dialer
        .dial_quic(
            listener.local_addr(),
            client_config(&keypair, &[b"other"]),
            "l",
        )
        .unwrap();

    let err = tokio::time::timeout(TIMEOUT, outbound)
        .await
        .expect("dial neither rejected nor timed out")
        .unwrap_err();
    // An ALPN-mismatch handshake failure signalled by the server, not a connection refusal.
    assert_alpn_mismatch(&err);
    // The rejection happened server-side before a connection existed: nothing was delivered.
    assert!(libp2p_rx.try_next().is_err());
    assert!(h3_rx.try_next().is_err());
}

/// A client offering no ALPN at all is routed to the default config, which rejects the
/// handshake (an allowlist is always enforced): same failure mode as an unknown ALPN.
#[tokio::test]
async fn absent_alpn_is_rejected_by_default_config() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (libp2p_tx, mut libp2p_rx) = mpsc::channel(8);
    let (h3_tx, mut h3_rx) = mpsc::channel(8);
    listener
        .register(
            LIBP2P.to_vec(),
            server_config(&keypair, &[LIBP2P]),
            libp2p_tx,
        )
        .unwrap();
    listener
        .register(H3.to_vec(), server_config(&keypair, &[H3]), h3_tx)
        .unwrap();

    let dialer = endpoint();
    let outbound = dialer
        .dial_quic(listener.local_addr(), client_config(&keypair, &[]), "l")
        .unwrap();

    let err = tokio::time::timeout(TIMEOUT, outbound)
        .await
        .expect("dial neither rejected nor timed out")
        .unwrap_err();
    assert_alpn_mismatch(&err);
    assert!(libp2p_rx.try_next().is_err());
    assert!(h3_rx.try_next().is_err());
}

/// A single registered protocol takes the direct accept path (no peek-dependent branch).
#[tokio::test]
async fn single_registration_accepts_directly() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (tx, mut rx) = mpsc::channel(8);
    listener
        .register(LIBP2P.to_vec(), server_config(&keypair, &[LIBP2P]), tx)
        .unwrap();

    let dialer = endpoint();
    let outbound = dialer
        .dial_quic(
            listener.local_addr(),
            client_config(&keypair, &[LIBP2P]),
            "l",
        )
        .unwrap();
    let inbound = recv(&mut rx).await;
    let (outbound, inbound) = tokio::join!(outbound, inbound);
    outbound.unwrap();
    inbound.unwrap();
}

/// Registering the same ALPN twice is rejected.
#[tokio::test]
async fn duplicate_alpn_is_rejected() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (tx1, _rx1) = mpsc::channel(8);
    let (tx2, _rx2) = mpsc::channel(8);
    listener
        .register(LIBP2P.to_vec(), server_config(&keypair, &[LIBP2P]), tx1)
        .unwrap();
    let err = listener
        .register(LIBP2P.to_vec(), server_config(&keypair, &[LIBP2P]), tx2)
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateAlpn(_)));
}

/// A connection whose registering protocol has gone away (receiver dropped) is refused.
#[tokio::test]
async fn dropped_sink_refuses_connections() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (tx, rx) = mpsc::channel(8);
    listener
        .register(LIBP2P.to_vec(), server_config(&keypair, &[LIBP2P]), tx)
        .unwrap();
    drop(rx);

    let dialer = endpoint();
    let outbound = dialer
        .dial_quic(
            listener.local_addr(),
            client_config(&keypair, &[LIBP2P]),
            "l",
        )
        .unwrap();
    let result = tokio::time::timeout(TIMEOUT, outbound)
        .await
        .expect("dial neither refused nor timed out");
    assert!(result.is_err());
}

/// Unregistering the default promotes the next registered ALPN to default: unmatched
/// offers now land on its sink.
#[tokio::test]
async fn unregister_promotes_next_default() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let (libp2p_tx, _libp2p_rx) = mpsc::channel(8);
    let (h3_tx, mut h3_rx) = mpsc::channel(8);
    listener
        .register(
            LIBP2P.to_vec(),
            server_config(&keypair, &[LIBP2P]),
            libp2p_tx,
        )
        .unwrap();
    listener
        .register(H3.to_vec(), server_config(&keypair, &[H3, FALLBACK]), h3_tx)
        .unwrap();
    listener.unregister(LIBP2P);

    let dialer = endpoint();
    let outbound = dialer
        .dial_quic(
            listener.local_addr(),
            client_config(&keypair, &[FALLBACK]),
            "l",
        )
        .unwrap();
    let inbound = recv(&mut h3_rx).await;
    let (outbound, inbound) = tokio::join!(outbound, inbound);
    assert_eq!(negotiated_alpn(&outbound.unwrap()), FALLBACK);
    assert_eq!(negotiated_alpn(&inbound.unwrap()), FALLBACK);
}

/// Updating the config of an unregistered ALPN errors; a registered one succeeds.
#[tokio::test]
async fn update_server_config_requires_registration() {
    let keypair = Keypair::generate_ed25519();
    let listener = endpoint();
    let cfg = server_config(&keypair, &[LIBP2P]);
    let err = listener
        .update_server_config(LIBP2P, cfg.clone())
        .unwrap_err();
    assert!(matches!(err, Error::UnknownAlpn(_)));

    let (tx, _rx) = mpsc::channel(8);
    listener.register(LIBP2P.to_vec(), cfg, tx).unwrap();
    listener
        .update_server_config(LIBP2P, server_config(&keypair, &[LIBP2P]))
        .unwrap();
}
