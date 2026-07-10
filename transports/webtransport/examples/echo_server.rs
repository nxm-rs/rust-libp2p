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

//! A native libp2p WebTransport echo server, mirroring the Go `echo-server` used by the
//! `webtransport-tests` browser harness.
//!
//! It listens on a native WebTransport address, prints/serves its full multiaddr (including
//! `/certhash` and `/p2p/<peer>`) over plain HTTP on `127.0.0.1:4455` (with permissive CORS so a
//! browser can fetch it), and for every inbound connection:
//!  * opens one outbound stream and writes a single `1` byte (so dialers can exercise *inbound*
//!    streams), and
//!  * echoes every inbound stream back to the sender.
//!
//! Run with `cargo run -p libp2p-webtransport --example echo_server`.

use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt, future::poll_fn};
use libp2p_core::{
    Multiaddr, Transport as _,
    multiaddr::Protocol,
    muxing::{StreamMuxerBox, StreamMuxerExt, SubstreamBox},
    transport::{ListenerId, TransportEvent},
};
use libp2p_identity::Keypair;
use libp2p_webtransport::{Certificate, Config, Transport};
use time::{OffsetDateTime, ext::NumericalDuration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
    let cert = Certificate::generate(not_before).expect("generate certificate");

    let mut transport = Transport::new(Config::new(&keypair, cert))
        .map(|(peer, conn), _| (peer, StreamMuxerBox::new(conn)))
        .boxed();

    transport
        .listen_on(
            ListenerId::next(),
            "/ip4/127.0.0.1/udp/0/quic-v1/webtransport".parse().unwrap(),
        )
        .unwrap();

    loop {
        match transport.select_next_some().await {
            TransportEvent::NewAddress { listen_addr, .. } => {
                let addr = listen_addr.with(Protocol::P2p(peer_id));
                println!("Listening on {addr}");
                tokio::spawn(serve_addr(addr));
            }
            TransportEvent::Incoming { upgrade, .. } => {
                tokio::spawn(async move {
                    match upgrade.await {
                        Ok((peer, conn)) => {
                            tracing::info!(%peer, "accepted connection");
                            serve_conn(conn).await;
                        }
                        Err(e) => tracing::warn!("inbound upgrade failed: {e}"),
                    }
                });
            }
            _ => {}
        }
    }
}

/// Drive a single accepted connection.
///
/// Mirrors the go-libp2p echo-server: eagerly open outbound streams (each writing a single `1`
/// byte so the remote can exercise *inbound* streams) *and* accept inbound streams, echoing both.
/// QUIC flow-control bounds how many unaccepted outbound streams we open at once, so this keeps
/// pace with what the remote actually accepts (the websys test suite opens many concurrent
/// streams in both directions over a single connection).
async fn serve_conn(mut conn: StreamMuxerBox) {
    use std::task::Poll;

    use futures::future::Either;

    loop {
        let next = poll_fn(|cx| {
            // Drive connection-level events (e.g. address changes), then make progress on opening
            // an outbound stream or accepting an inbound one — whichever is ready first.
            let _ = conn.poll_unpin(cx)?;
            if let Poll::Ready(stream) = conn.poll_outbound_unpin(cx) {
                return Poll::Ready(stream.map(Either::Left));
            }
            if let Poll::Ready(stream) = conn.poll_inbound_unpin(cx) {
                return Poll::Ready(stream.map(Either::Right));
            }
            Poll::Pending
        })
        .await;

        match next {
            // Outbound stream we opened: announce it with a single byte, then echo.
            Ok(Either::Left(mut stream)) => {
                tokio::spawn(async move {
                    if stream.write_all(b"1").await.is_ok() {
                        let _ = stream.flush().await;
                        echo(stream).await;
                    }
                });
            }
            // Inbound stream opened by the remote: echo it.
            Ok(Either::Right(stream)) => {
                tokio::spawn(echo(stream));
            }
            Err(e) => {
                tracing::debug!("connection closed: {e}");
                break;
            }
        }
    }
}

/// Echo everything read on a stream back to the sender.
async fn echo(mut stream: SubstreamBox) {
    let mut buf = [0u8; 2048];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = stream.flush().await;
            }
        }
    }
}

/// Minimal HTTP/1.1 server on `127.0.0.1:4455` that returns the WebTransport multiaddr as text,
/// matching the discovery endpoint used by the `webtransport-tests` browser harness.
async fn serve_addr(addr: Multiaddr) {
    let listener = TcpListener::bind(("127.0.0.1", 4455))
        .await
        .expect("bind addr reporter");
    let body = addr.to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Cross-Origin-Resource-Policy: cross-origin\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let response = response.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            // Read (and discard) the request line/headers.
            let _ = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut buf)).await;
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        });
    }
}
