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

//! Interop test: a native rust-libp2p WebTransport node dials a **go-libp2p** WebTransport server.
//!
//! ## Known limitation (upstream `wtransport` bug, fixable)
//!
//! This direction (native rust dialing a go-libp2p WebTransport *listener*) currently **fails** —
//! but **not** because of a WebTransport draft mismatch (both sides speak draft-02-compatible
//! framing and the HTTP/3 SETTINGS exchange succeeds). The cause is an HTTP/3 header-ordering bug
//! in `wtransport` 0.7.1: it stores CONNECT request headers in a `HashMap` and its QPACK encoder
//! emits them in hash order. When this dialer adds the `Sec-Webtransport-Http3-Draft02: 1` header
//! (which go-libp2p *requires*), that regular header is serialized *before* the `:`-pseudo-headers,
//! violating RFC 9114 §4.3. go-libp2p (quic-go) enforces the rule and resets the request stream
//! with `H3_MESSAGE_ERROR` (0x10E / 270); `wtransport` then tears down its own connection, which
//! surfaces as `Connect(ConnectionError(LocallyClosed))`. It is a catch-22: go requires the header,
//! but `wtransport`'s only API to add it (`ConnectOptions::add_header`) corrupts pseudo-header
//! ordering.
//!
//! The fix is small and belongs upstream in `wtransport-proto` (make the CONNECT header collection
//! order-preserving and always emit pseudo-headers first); a `[patch.crates-io]` fork can carry it
//! in the interim. The reverse direction (go→this listener), browser→this listener, and
//! native↔native all work, because only go enforces the ordering that `wtransport` violates. The
//! CI job that runs this test is non-blocking until the `wtransport` fix lands.
//!
//! The go server is the `wasm-tests/webtransport-tests/echo-server` (go-libp2p), which advertises
//! its multiaddr over HTTP on `127.0.0.1:4455`. This is ignored by default because it requires
//! that binary; run it with:
//!
//! ```text
//! GO_ECHO_SERVER=/path/to/echo-server \
//!   cargo test -p libp2p-webtransport --test interop_go -- --ignored --nocapture
//! ```

use std::{
    env,
    io::{Read as _, Write as _},
    net::TcpStream,
    process::{Child, Command, Stdio},
    time::Duration,
};

use futures::{AsyncReadExt, AsyncWriteExt, future::poll_fn};
use libp2p_core::{
    Endpoint, Multiaddr, Transport as _,
    multiaddr::Protocol,
    muxing::{StreamMuxerBox, StreamMuxerExt},
    transport::{DialOpts, PortUse},
};
use libp2p_identity::Keypair;
use libp2p_webtransport as webtransport;
use time::{OffsetDateTime, ext::NumericalDuration};

/// Kills the spawned child process when dropped.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires the go echo-server binary via the GO_ECHO_SERVER env var"]
async fn rust_native_dials_go_libp2p() {
    let go_bin = env::var("GO_ECHO_SERVER")
        .expect("set GO_ECHO_SERVER to the path of the compiled go echo-server binary");

    let child = Command::new(&go_bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn go echo-server");
    let _guard = ChildGuard(child);

    let addr: Multiaddr = fetch_server_addr().await.parse().expect("valid multiaddr");
    let expected_peer = match addr.iter().last() {
        Some(Protocol::P2p(peer)) => peer,
        other => panic!("expected /p2p in go addr, got {other:?}"),
    };

    let keypair = Keypair::generate_ed25519();
    let not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
    let cert = webtransport::Certificate::generate(not_before).unwrap();
    let mut transport = webtransport::Transport::new(webtransport::Config::new(&keypair, cert));

    let (peer, conn) = transport
        .dial(
            addr,
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
        )
        .expect("dial")
        .await
        .expect("connection to go-libp2p established");

    assert_eq!(
        peer, expected_peer,
        "Noise-authenticated peer id matches go server"
    );

    let mut conn = StreamMuxerBox::new(conn);

    // Open an outbound stream; the go echo-server echoes everything via io.Copy.
    let mut stream = poll_fn(|cx| conn.poll_outbound_unpin(cx))
        .await
        .expect("open outbound stream");

    let mut send = [0u8; 1024];
    let mut recv = [0u8; 1024];
    for round in 0u8..16 {
        for (j, b) in send.iter_mut().enumerate() {
            *b = round.wrapping_mul(31).wrapping_add(j as u8);
        }
        stream.write_all(&send).await.expect("write to go");
        stream.flush().await.expect("flush to go");
        stream
            .read_exact(&mut recv)
            .await
            .expect("read echo from go");
        assert_eq!(send, recv, "go echoed the bytes back");
    }
}

/// Fetch the echo-server's multiaddr from its HTTP discovery endpoint on `127.0.0.1:4455`,
/// retrying until it comes up.
async fn fetch_server_addr() -> String {
    for _ in 0..100 {
        if let Some(addr) = try_fetch_addr()
            && !addr.is_empty()
        {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("go echo-server did not report an address on 127.0.0.1:4455 in time");
}

fn try_fetch_addr() -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", 4455)).ok()?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let body = response.split("\r\n\r\n").nth(1)?;
    Some(body.trim().to_string())
}
