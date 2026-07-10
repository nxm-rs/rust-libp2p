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
//! ## Certificate rotation
//!
//! Because the self-signed certificate is short-lived (under 14 days, the browser ceiling for
//! hash-pinned certificates), a listener cannot serve a single fixed certificate forever: once it
//! expires the advertised `/certhash` stops matching any servable certificate and the listener goes
//! dead. Instead a listener manages an **ordered set of certificates** and rotates automatically.
//!
//! Following the spec and go-libp2p, certificates use **sequential validity windows with a one-hour
//! clock-skew backdate on each edge** (served validity `= certValidity - 2h`, keeping the total
//! window under 14 days). A listener advertises **two** certificate hashes in its multiaddr (the
//! current and next certificates) and reports **up to three** over Noise (additionally a
//! recently-expired one, which the spec recommends so in-flight dialers still verify). Before the
//! active certificate expires the listener generates a successor, hot-swaps the endpoint TLS config
//! *without dropping live connections*, and re-publishes its listen address (an
//! [`AddressExpired`](libp2p_core::transport::TransportEvent::AddressExpired) followed by a
//! [`NewAddress`](libp2p_core::transport::TransportEvent::NewAddress)).
//!
//! Use [`Config::generate`] to start from a current+next pair; [`Config::new`] (single certificate)
//! still self-rotates.
//!
//! ## Configuring the transport
//!
//! [`Config`] has private fields and is `#[non_exhaustive]`; build one with [`Config::new`],
//! [`Config::new_with_certs`], or [`Config::generate`], then tune it with the chained
//! `mut self -> Self` setters (mirroring `libp2p-quic`'s `Config`):
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use libp2p_identity::Keypair;
//! use libp2p_webtransport::{Certificate, Config};
//! use time::OffsetDateTime;
//!
//! let keypair = Keypair::generate_ed25519();
//! let cert = Certificate::generate(OffsetDateTime::now_utc())?;
//! let config = Config::new(&keypair, cert)
//!     .max_idle_timeout(30_000) // milliseconds; 0 means "infinite" — use with care
//!     .keep_alive_interval(Duration::from_secs(5))
//!     .max_concurrent_stream_limit(256)
//!     .disable_path_mtu_discovery();
//! # Ok::<(), libp2p_webtransport::CertificateError>(())
//! ```
//!
//! ## Certificates
//!
//! [`Certificate`] can be persisted and restored across restarts with
//! [`Certificate::to_bytes`] and [`Certificate::parse`]. The serialized form begins with a single
//! version byte ([`SERIALIZATION_VERSION`]); [`Certificate::parse`] is total (it never panics and
//! bounds its allocations) and rejects a blob written by an incompatible build with
//! [`CertificateError::UnsupportedVersion`]. The serialized blob **contains the private key in the
//! clear** — store it with filesystem-level confidentiality (mode `0600` or a secret store).
//!
//! ```no_run
//! use libp2p_webtransport::Certificate;
//! use time::OffsetDateTime;
//!
//! let cert = Certificate::generate(OffsetDateTime::now_utc())?;
//! let bytes = cert.to_bytes(); // persist (0600!)
//! let restored = Certificate::parse(&bytes)?; // restore on the next start
//! assert_eq!(restored, cert);
//! # Ok::<(), libp2p_webtransport::CertificateError>(())
//! ```
//!
//! # Shared endpoint, socket reuse & hole punching
//!
//! The transport obtains all its QUIC connections from a `libp2p-quicreuse` endpoint holder;
//! `wtransport` acts purely as the WebTransport/H3 protocol engine over connections it did not
//! establish (`IncomingSessionFuture::with_quic_connecting` inbound, `connect_over_quic`
//! outbound) and never owns a socket. [`Transport::with_shared_endpoint`] accepts an externally
//! shared holder, so WebTransport can co-listen with plain QUIC on **one UDP port**,
//! demultiplexed by the negotiated ALPN (`h3` here, `libp2p` for raw QUIC). A transport built
//! with [`Transport::new`] uses a private holder per listener instead.
//!
//! The holder's ALPN peek is a routing hint only. Each registered `ServerConfig` still enforces
//! its own ALPN allowlist and its own client-auth policy: the `h3` route serves the
//! certhash-pinned WebTransport certificate with no client auth, while the `libp2p` route keeps
//! mutual TLS authentication. A misrouted connection therefore fails its handshake with an ALPN
//! mismatch; it is never served under the wrong authentication policy.
//!
//! Dials are routed through a holder selected from the `(role, port_use)` tuple, exactly like
//! `libp2p-quic`:
//!
//! * **`PortUse::Reuse`** (the default for ordinary dials, and what DCUtR's `override_role()` emits
//!   as `(Listener, Reuse)`) dials from an existing listener's holder when one exists, i.e. the
//!   listener's own UDP socket, preserving the NAT 4-tuple. Without a listener it reuses the
//!   constructor-shared holder or a cached per-family ephemeral dialer holder.
//! * **`(Listener, New)`** (a coordinated DCUtR hole-punch) also dials from the listener's holder,
//!   so the WebTransport session rides the hole-punched path.
//!
//! # Limitations
//!
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
    certificate::{CertHash, Certificate, Error as CertificateError, SERIALIZATION_VERSION},
    config::{Config, ConfigError},
    connection::{Connection, Stream},
    transport::Transport,
};

/// Errors that may happen on the [`Transport`] or a single [`Connection`].
///
/// This enum is `#[non_exhaustive]`: the crate is unreleased and may add further variants without
/// a breaking change, so downstream `match`es must include a trailing `_ =>` arm. A match without
/// one does not compile:
///
/// ```compile_fail
/// use libp2p_webtransport::Error;
/// fn describe(e: &Error) -> &'static str {
///     match e {
///         Error::UnknownRemotePeerId => "unknown peer",
///         // no wildcard arm: rejected because `Error` is `#[non_exhaustive]`
///     }
/// }
/// ```
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

    /// Error while initiating the QUIC connection on the shared endpoint (before the WebTransport
    /// handshake), e.g. an invalid client TLS/transport config.
    #[error(transparent)]
    QuicConnect(#[from] quinn::ConnectError),

    /// Error while establishing the QUIC connection on the shared endpoint (before the WebTransport
    /// handshake).
    #[error(transparent)]
    QuicConnection(#[from] quinn::ConnectionError),

    /// The multiaddr did not contain any certificate hashes, which are required to dial a
    /// libp2p WebTransport server that uses a self-signed certificate.
    #[error("Cannot dial a WebTransport address without certificate hashes")]
    MissingCerthashes,

    /// A certificate hash in the multiaddr used an unsupported multihash code (only SHA-256 is
    /// supported).
    #[error("Unsupported certificate hash; only SHA-256 multihashes are supported")]
    UnsupportedCerthash,

    /// Invalid certificate configuration (e.g. an empty certificate set).
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Deprecated/retained for API stability: WebTransport hole-punch dials
    /// (`DialOpts { role: Endpoint::Listener, port_use: PortUse::New, .. }`) are now supported by
    /// dialing from the listener's shared `quinn::Endpoint`, so this variant is no longer returned.
    /// It is kept only so existing `match` arms keep compiling.
    #[error("WebTransport does not support dialing as a listener (hole punching)")]
    HolePunchingUnsupported,
}

impl From<Error> for TransportError<Error> {
    fn from(value: Error) -> Self {
        TransportError::Other(value)
    }
}
