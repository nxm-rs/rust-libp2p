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

//! Integration tests for single-port co-listening: plain QUIC (`/quic-v1`) and WebTransport
//! (`/webtransport`) served from ONE UDP socket via a shared `libp2p-quicreuse` endpoint holder,
//! demultiplexed by the ALPN offered in the client's Initial packet.
//!
//! The critical regression guard here is auth preservation: the plain-QUIC inbound path on the
//! shared listener must keep libp2p mutual TLS authentication. The holder selects the complete
//! `ServerConfig` per registered ALPN, so the `libp2p` route carries the mutual-auth verifier and
//! the `h3` route carries the no-client-auth WebTransport config; sharing the socket must never
//! serve plain QUIC without client certificate verification.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt, future};
use libp2p_core::{
    Endpoint, Multiaddr, Transport,
    multiaddr::Protocol,
    muxing::{StreamMuxerBox, StreamMuxerExt},
    transport::{Boxed, DialOpts, ListenerId, PortUse, TransportEvent},
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_quicreuse::SharedQuicEndpoint;
use libp2p_webtransport as webtransport;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use time::{OffsetDateTime, ext::NumericalDuration};

const TIMEOUT: Duration = Duration::from_secs(30);

fn quic_transport(
    keypair: &Keypair,
    holder: Option<Arc<SharedQuicEndpoint>>,
) -> Boxed<(PeerId, StreamMuxerBox)> {
    let config = libp2p_quic::Config::new(keypair);
    let transport = match holder {
        Some(holder) => libp2p_quic::tokio::Transport::with_shared_endpoint(config, holder),
        None => libp2p_quic::tokio::Transport::new(config),
    };
    transport
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed()
}

fn wt_transport(
    keypair: &Keypair,
    holder: Option<Arc<SharedQuicEndpoint>>,
) -> Boxed<(PeerId, StreamMuxerBox)> {
    // A certificate valid since yesterday so that the validity window is already open.
    let not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
    let cert = webtransport::Certificate::generate(not_before).expect("generate cert");
    let config = webtransport::Config::new(keypair, cert);
    let transport = match holder {
        Some(holder) => webtransport::Transport::with_shared_endpoint(config, holder),
        None => webtransport::Transport::new(config),
    };
    transport
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed()
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

fn udp_port(addr: &Multiaddr) -> u16 {
    addr.iter()
        .find_map(|p| match p {
            Protocol::Udp(port) => Some(port),
            _ => None,
        })
        .expect("address has a udp component")
}

/// One node serving both protocols from a single shared UDP socket: a plain QUIC listener
/// (`libp2p` ALPN, mutual auth) and a WebTransport listener (`h3` ALPN, certhash-pinned) both
/// registered on the same `SharedQuicEndpoint`.
struct MixedListener {
    peer_id: PeerId,
    port: u16,
    holder: Arc<SharedQuicEndpoint>,
    quic: Boxed<(PeerId, StreamMuxerBox)>,
    wt: Boxed<(PeerId, StreamMuxerBox)>,
    quic_addr: Multiaddr,
    wt_addr: Multiaddr,
}

async fn mixed_listener() -> MixedListener {
    let holder = Arc::new(SharedQuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let port = holder.local_addr().port();

    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();

    let mut quic = quic_transport(&keypair, Some(Arc::clone(&holder)));
    let mut wt = wt_transport(&keypair, Some(Arc::clone(&holder)));

    // An explicit port of 0 matches the shared endpoint's bound address.
    let quic_addr = start_listening(&mut quic, "/ip4/127.0.0.1/udp/0/quic-v1").await;
    let wt_addr = start_listening(&mut wt, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;

    MixedListener {
        peer_id,
        port,
        holder,
        quic,
        wt,
        quic_addr,
        wt_addr,
    }
}

/// Accept one inbound connection, echo `PING` -> `PONG` on its first inbound stream, and return
/// the authenticated remote peer together with the local address the connection was observed on.
async fn accept_and_echo(
    transport: &mut Boxed<(PeerId, StreamMuxerBox)>,
) -> Result<(PeerId, Multiaddr), String> {
    loop {
        if let TransportEvent::Incoming {
            upgrade,
            local_addr,
            ..
        } = transport.select_next_some().await
        {
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
            futures_timer::Delay::new(Duration::from_secs(1)).await;

            return Ok((remote_peer, local_addr));
        }
    }
}

/// Dial `addr`, send `PING` on a fresh outbound stream, expect `PONG`, and return the
/// authenticated remote peer.
async fn dial_and_echo(
    transport: &mut Boxed<(PeerId, StreamMuxerBox)>,
    addr: Multiaddr,
) -> Result<PeerId, String> {
    let (remote_peer, mut conn) = transport
        .dial(
            addr,
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

    Ok(remote_peer)
}

/// Drive one listener-side accept+echo against one dialer-side dial+echo, bubbling errors up.
/// Returns (peer observed by the listener, peer observed by the dialer, local address the
/// listener observed the connection on).
async fn exchange(
    listener: &mut Boxed<(PeerId, StreamMuxerBox)>,
    dialer: &mut Boxed<(PeerId, StreamMuxerBox)>,
    dial_addr: Multiaddr,
) -> (PeerId, PeerId, Multiaddr) {
    let accept = accept_and_echo(listener);
    let dial = dial_and_echo(dialer, dial_addr);
    futures::pin_mut!(accept);
    futures::pin_mut!(dial);

    let (listener_out, dialer_out) = tokio::time::timeout(TIMEOUT, async {
        match future::select(accept, dial).await {
            future::Either::Left((l, dial_fut)) => (Some(l), dial_fut.await),
            future::Either::Right((d, accept_fut)) => match d {
                Ok(peer) => (Some(accept_fut.await), Ok(peer)),
                Err(e) => (None, Err(e)),
            },
        }
    })
    .await
    .expect("exchange timed out");

    let peer_on_dialer = dialer_out.expect("dialer side");
    let (peer_on_listener, local_addr) = listener_out
        .expect("listener ran on success")
        .expect("listener side");
    (peer_on_listener, peer_on_dialer, local_addr)
}

/// One address, one socket, two protocols: a plain-QUIC dialer and a WebTransport dialer both
/// connect to the same UDP port, and both inbound connections are observed on that same local
/// port (one socket, ALPN-demultiplexed).
#[tokio::test]
async fn single_socket_serves_quic_and_webtransport() {
    let mut node = mixed_listener().await;

    // Both listeners advertise the shared socket's port: one address to configure.
    assert_eq!(udp_port(&node.quic_addr), node.port);
    assert_eq!(udp_port(&node.wt_addr), node.port);

    // A plain QUIC dialer connects and completes the mutual-auth handshake.
    let quic_keypair = Keypair::generate_ed25519();
    let mut quic_dialer = quic_transport(&quic_keypair, None);
    let (peer_on_listener, peer_on_dialer, quic_local) =
        exchange(&mut node.quic, &mut quic_dialer, node.quic_addr.clone()).await;
    assert_eq!(peer_on_dialer, node.peer_id);
    assert_eq!(peer_on_listener, quic_keypair.public().to_peer_id());

    // A WebTransport dialer connects to the SAME port and completes the certhash + Noise
    // handshake.
    let wt_keypair = Keypair::generate_ed25519();
    let mut wt_dialer = wt_transport(&wt_keypair, None);
    let wt_dial_addr = node.wt_addr.clone().with(Protocol::P2p(node.peer_id));
    let (peer_on_listener, peer_on_dialer, wt_local) =
        exchange(&mut node.wt, &mut wt_dialer, wt_dial_addr).await;
    assert_eq!(peer_on_dialer, node.peer_id);
    assert_eq!(peer_on_listener, wt_keypair.public().to_peer_id());

    // Both inbound connections were observed on the identical local port: one socket.
    assert_eq!(udp_port(&quic_local), node.port);
    assert_eq!(udp_port(&wt_local), node.port);
    assert_eq!(udp_port(&quic_local), udp_port(&wt_local));
}

/// ALPN demux is deterministic: from the same listener, and with both dials in flight
/// concurrently, an `h3` dial yields a WebTransport muxer (certhash-pinned TLS + H3 CONNECT +
/// Noise all complete) and a `libp2p` dial yields a QUIC muxer (mutual-auth TLS completes).
/// Each handshake can only complete against its own `ServerConfig`, so a successful echo on each
/// transport proves the connection was routed to the protocol that registered the offered ALPN.
#[tokio::test]
async fn alpn_demux_routes_h3_to_webtransport_and_libp2p_to_quic() {
    let mut node = mixed_listener().await;

    let quic_keypair = Keypair::generate_ed25519();
    let mut quic_dialer = quic_transport(&quic_keypair, None);
    let wt_keypair = Keypair::generate_ed25519();
    let mut wt_dialer = wt_transport(&wt_keypair, None);
    let wt_dial_addr = node.wt_addr.clone().with(Protocol::P2p(node.peer_id));

    let quic_exchange = exchange(&mut node.quic, &mut quic_dialer, node.quic_addr.clone());
    let wt_exchange = exchange(&mut node.wt, &mut wt_dialer, wt_dial_addr);
    let (
        (quic_peer_on_listener, quic_peer_on_dialer, _),
        (wt_peer_on_listener, wt_peer_on_dialer, _),
    ) = future::join(quic_exchange, wt_exchange).await;

    assert_eq!(quic_peer_on_dialer, node.peer_id);
    assert_eq!(quic_peer_on_listener, quic_keypair.public().to_peer_id());
    assert_eq!(wt_peer_on_dialer, node.peer_id);
    assert_eq!(wt_peer_on_listener, wt_keypair.public().to_peer_id());

    // No crossover: neither transport has a further inbound connection pending.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), node.quic.select_next_some())
            .await
            .is_err(),
        "QUIC listener must not receive the WebTransport connection"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(500), node.wt.select_next_some())
            .await
            .is_err(),
        "WebTransport listener must not receive the QUIC connection"
    );
}

/// Accepts any server certificate: these clients probe the *server's* client-auth policy, so
/// server verification is irrelevant to what is being tested.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A QUIC client offering the `libp2p` ALPN with the given client identity: `None` presents no
/// client certificate at all; `Some` presents the given (non-libp2p) certificate chain.
fn probe_client_config(
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> quinn::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)));
    let mut tls = match identity {
        None => builder.with_no_client_auth(),
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).unwrap(),
    };
    tls.alpn_protocols = vec![b"libp2p".to_vec()];
    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ))
}

/// A syntactically valid self-signed certificate that is NOT a libp2p certificate (it lacks the
/// libp2p extension binding the host key).
fn non_libp2p_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["l".to_string()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    (vec![cert.der().clone()], key)
}

/// Resolve a client-side dial to the server's rejection.
///
/// In TLS 1.3 the client sends its (possibly empty) certificate together with its `Finished`, so
/// the client-side `Connecting` can resolve before the server has processed the certificate and
/// aborted. The rejection then surfaces as the connection being closed immediately after.
async fn await_rejection(connecting: quinn::Connecting) -> quinn::ConnectionError {
    match tokio::time::timeout(TIMEOUT, connecting)
        .await
        .expect("dial neither rejected nor timed out")
    {
        Err(e) => e,
        Ok(connection) => tokio::time::timeout(TIMEOUT, connection.closed())
            .await
            .expect("connection neither closed nor timed out"),
    }
}

/// The QUIC transport error class for TLS handshake failures (`CRYPTO_ERROR`, alert carried in
/// the low byte).
fn assert_crypto_error(err: &quinn::ConnectionError) {
    match err {
        quinn::ConnectionError::ConnectionClosed(close) => {
            let code = u64::from(close.error_code);
            assert!(
                (0x100..=0x1ff).contains(&code),
                "expected a TLS handshake failure, got: {close:?}"
            );
        }
        other => panic!("expected a server-signalled handshake failure, got: {other:?}"),
    }
}

/// Consume the inbound connection a rejected dial left on the QUIC listener (if it surfaced at
/// all) and assert its upgrade fails: no unauthenticated connection ever reaches the application.
async fn expect_rejected_inbound(transport: &mut Boxed<(PeerId, StreamMuxerBox)>) {
    match tokio::time::timeout(Duration::from_secs(5), transport.select_next_some()).await {
        Ok(TransportEvent::Incoming { upgrade, .. }) => {
            let upgraded = tokio::time::timeout(TIMEOUT, upgrade)
                .await
                .expect("upgrade neither failed nor timed out");
            assert!(
                upgraded.is_err(),
                "unauthenticated inbound connection must not upgrade"
            );
        }
        Ok(e) => panic!("unexpected event: {e:?}"),
        // The connection may also fail before the listener surfaces it; both outcomes reject.
        Err(_) => {}
    }
}

/// AUTH PRESERVATION: the plain-QUIC inbound path on the shared listener still performs libp2p
/// mutual authentication. A QUIC client offering the `libp2p` ALPN but presenting no client
/// certificate, or a non-libp2p one, is rejected by the TLS handshake; a client with a proper
/// libp2p certificate succeeds on the very same listener. This proves the holder selected the
/// mutual-auth `ServerConfig` for the `libp2p` ALPN and did not serve plain QUIC with a
/// no-client-auth config.
#[tokio::test]
async fn shared_listener_preserves_quic_mutual_auth() {
    let mut node = mixed_listener().await;
    let server_addr: SocketAddr = node.holder.local_addr();

    let dialer = SharedQuicEndpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();

    // 1. No client certificate: the server's mutual-auth verifier demands one, so the handshake
    //    fails with the TLS `certificate_required` alert (116). Under the Driver B regression
    //    (a single no-client-auth config for the whole endpoint) this dial would SUCCEED.
    let connecting = dialer
        .dial_quic(server_addr, probe_client_config(None), "l")
        .unwrap();
    let err = await_rejection(connecting).await;
    match &err {
        quinn::ConnectionError::ConnectionClosed(close) => assert_eq!(
            close.error_code,
            quinn::TransportErrorCode::crypto(116),
            "expected certificate_required, got: {close:?}"
        ),
        other => panic!("expected a server-signalled handshake failure, got: {other:?}"),
    }

    // The connection was routed to the QUIC transport (the `libp2p` route was selected), but its
    // upgrade must fail: no unauthenticated connection ever surfaces to the application.
    expect_rejected_inbound(&mut node.quic).await;

    // 2. A syntactically valid but non-libp2p client certificate is likewise rejected by the
    //    mutual-auth verifier (a TLS handshake failure signalled by the server).
    let connecting = dialer
        .dial_quic(
            server_addr,
            probe_client_config(Some(non_libp2p_identity())),
            "l",
        )
        .unwrap();
    let err = await_rejection(connecting).await;
    assert_crypto_error(&err);
    expect_rejected_inbound(&mut node.quic).await;

    // 3. Positive control on the same listener and socket: a client presenting a proper libp2p
    //    certificate completes the handshake, so the rejections above are attributable to client
    //    authentication and not to a broken listener.
    let client_keypair = Keypair::generate_ed25519();
    let tls = libp2p_tls::make_client_config(&client_keypair, None).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    let connecting = dialer.dial_quic(server_addr, client_config, "l").unwrap();
    let accept = async {
        loop {
            if let TransportEvent::Incoming { upgrade, .. } = node.quic.select_next_some().await {
                return upgrade.await;
            }
        }
    };
    let (outbound, inbound) = tokio::time::timeout(TIMEOUT, future::join(connecting, accept))
        .await
        .expect("mutual-auth exchange timed out");
    outbound.expect("mutual-auth dial succeeds");
    let (peer, _muxer) = inbound.expect("mutual-auth inbound upgrade succeeds");
    assert_eq!(peer, client_keypair.public().to_peer_id());
}
