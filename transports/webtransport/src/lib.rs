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
    config::{Config, ConfigError},
    connection::{Connection, Stream},
    transport::Transport,
};

/// Errors that may happen on the [`Transport`] or a single [`Connection`].
///
/// This enum is `#[non_exhaustive]`: the crate is unreleased and may add further variants without
/// a breaking change, so downstream `match`es must include a wildcard arm.
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

    /// Invalid certificate configuration (e.g. an empty certificate set).
    #[error(transparent)]
    Config(#[from] ConfigError),
}

impl From<Error> for TransportError<Error> {
    fn from(value: Error) -> Self {
        TransportError::Other(value)
    }
}
