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

async fn start_listening(transport: &mut Boxed<(PeerId, StreamMuxerBox)>, addr: &str) -> Multiaddr {
    transport
        .listen_on(ListenerId::next(), addr.parse().unwrap())
        .unwrap();

    match transport.select_next_some().await {
        TransportEvent::NewAddress { listen_addr, .. } => listen_addr,
        e => panic!("Unexpected event: {e:?}"),
    }
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
    let (dialer_peer_id, mut dialer) = create_transport();

    let listen_addr =
        start_listening(&mut listener, "/ip4/127.0.0.1/udp/0/quic-v1/webtransport").await;
    // The listen address already carries the `/certhash`; append the expected peer id.
    let dial_addr = listen_addr.with(Protocol::P2p(listener_peer_id));

    // Listener: accept one connection and echo `PING` -> `PONG` on the first inbound stream.
    let listener_task = async move {
        loop {
            if let TransportEvent::Incoming { upgrade, .. } = listener.select_next_some().await {
                let (remote_peer, mut conn) = upgrade.await.expect("inbound upgrade");

                let mut stream = future::poll_fn(|cx| {
                    let _ = conn.poll_unpin(cx)?;
                    conn.poll_inbound_unpin(cx)
                })
                .await
                .expect("inbound stream");

                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.expect("read PING");
                assert_eq!(&buf, b"PING");
                stream.write_all(b"PONG").await.expect("write PONG");
                stream.flush().await.expect("flush PONG");
                // Keep the connection alive briefly so the dialer can read the response.
                futures_timer::Delay::new(Duration::from_secs(1)).await;

                return remote_peer;
            }
        }
    };

    // Dialer: dial, open an outbound stream, send `PING`, expect `PONG`.
    let dialer_task = async move {
        let (remote_peer, mut conn) = dialer
            .dial(
                dial_addr,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                },
            )
            .expect("dial")
            .await
            .expect("connection established");

        let mut stream = future::poll_fn(|cx| {
            let _ = conn.poll_unpin(cx)?;
            conn.poll_outbound_unpin(cx)
        })
        .await
        .expect("outbound stream");

        stream.write_all(b"PING").await.expect("write PING");
        stream.flush().await.expect("flush PING");
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.expect("read PONG");
        assert_eq!(&buf, b"PONG");

        remote_peer
    };

    let (remote_on_listener, remote_on_dialer) = tokio::time::timeout(
        Duration::from_secs(30),
        future::join(listener_task, dialer_task),
    )
    .await
    .expect("test timed out");

    // Each side authenticated the other's libp2p identity via the Noise handshake.
    assert_eq!(remote_on_listener, dialer_peer_id);
    assert_eq!(remote_on_dialer, listener_peer_id);
}
