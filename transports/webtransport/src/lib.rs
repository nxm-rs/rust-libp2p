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

//! Implementation of the [WebTransport] transport for libp2p in native (non-browser)
//! environments.
//!
//! This transport runs WebTransport over HTTP/3 (QUIC) using the [`wtransport`] crate. It is the
//! native counterpart to [`libp2p-webtransport-websys`], which only runs in the browser and can
//! only dial. Together they enable WebTransport interoperability between native (e.g. x86) nodes
//! and WASM/browser nodes:
//!
//! * a browser (WASM) node can dial a native node (the native node listens),
//! * a native node can dial another native node,
//! * either peer of an established connection can open new streams.
//!
//! Authentication follows the [libp2p WebTransport specification][spec]: the server presents a
//! short-lived self-signed certificate whose SHA-256 hash is advertised in its multiaddr
//! (`/certhash`), and the libp2p identity is authenticated with a Noise handshake performed over
//! the first bidirectional stream (without `multistream-select`). The certificate hashes are
//! bound to the authenticated peer via the Noise `webtransport_certhashes` extension.
//!
//! # Limitations
//!
//! * **No DCUtR hole punching:** a coordinated hole-punch dial (`DialOpts { role:
//!   Endpoint::Listener, port_use: PortUse::New, .. }`) fails with
//!   [`Error::HolePunchingUnsupported`], because `wtransport`'s client endpoint cannot dial from
//!   the listener's socket.
//! * **`PortUse::Reuse` is not honoured:** ordinary dials always bind a fresh ephemeral socket.
//! * **Only the `h3` ALPN is offered** by the server.
//!
//! [WebTransport]: https://www.w3.org/TR/webtransport/
//! [`wtransport`]: https://docs.rs/wtransport
//! [`libp2p-webtransport-websys`]: https://docs.rs/libp2p-webtransport-websys
//! [spec]: https://github.com/libp2p/specs/blob/master/webtransport/README.md

mod certificate;
mod config;
mod connection;
mod transport;

pub(crate) use connection::Connecting;
use libp2p_core::transport::TransportError;
use wtransport::error::ConnectionError;

pub use self::{
    certificate::{CertHash, Certificate},
    config::Config,
    connection::{Connection, Stream},
    transport::Transport,
};

/// Errors that may happen on the [`Transport`] or a single [`Connection`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Error after the remote has been reached.
    #[error(transparent)]
    Connection(#[from] ConnectionError),

    /// I/O Error on a socket.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Unexpected HTTP endpoint of a libp2p WebTransport server {0}")]
    UnexpectedPath(String),

    #[error(transparent)]
    Authentication(#[from] libp2p_noise::Error),

    #[error("Unknown remote peer ID")]
    UnknownRemotePeerId,

    #[error("Handshake with the remote timed out")]
    HandshakeTimedOut,

    /// Error while establishing the WebTransport session as a dialer.
    #[error(transparent)]
    Connect(#[from] wtransport::error::ConnectingError),

    /// Error while opening a bidirectional stream.
    #[error(transparent)]
    StreamOpening(#[from] wtransport::error::StreamOpeningError),

    /// The multiaddr did not contain any certificate hashes, which are required to dial a
    /// libp2p WebTransport server that uses a self-signed certificate.
    #[error("Cannot dial a WebTransport address without certificate hashes")]
    MissingCerthashes,

    /// A certificate hash in the multiaddr used an unsupported multihash code (only SHA-256 is
    /// supported).
    #[error("Unsupported certificate hash; only SHA-256 multihashes are supported")]
    UnsupportedCerthash,

    /// Coordinated hole punching (DCUtR) was requested by dialing with
    /// `DialOpts { role: Endpoint::Listener, port_use: PortUse::New, .. }`, but this transport
    /// cannot dial from the listener's socket: the underlying `wtransport` API only exposes
    /// `connect` on a *client* endpoint, which always binds a fresh socket. Hole punching over
    /// WebTransport is therefore unsupported.
    #[error("WebTransport does not support dialing as a listener (hole punching)")]
    HolePunchingUnsupported,
}

impl From<Error> for TransportError<Error> {
    fn from(value: Error) -> Self {
        TransportError::Other(value)
    }
}
