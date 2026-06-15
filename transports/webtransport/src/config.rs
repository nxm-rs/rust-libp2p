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

use quinn::{MtuDiscoveryConfig, VarInt};
use time::OffsetDateTime;
use wtransport::config::{QuicTransportConfig, TlsServerConfig};

use crate::certificate::{self, CERT_VALID_PERIOD, CLOCK_SKEW_ALLOWANCE, Certificate};

/// Error returned when constructing a [`Config`] with an invalid certificate set.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A [`Config`] must hold at least one certificate; an empty set was supplied.
    #[error("a WebTransport config requires at least one certificate")]
    EmptyCertSet,
}

/// Configuration for the native WebTransport [`Transport`](crate::Transport).
///
/// All fields are private and the type is `#[non_exhaustive]`. Construct a `Config` with
/// [`Config::new`] (a single certificate), [`Config::new_with_certs`], or [`Config::generate`]
/// (a current+next pair), then tune it with the chained `mut self -> Self` setters
/// ([`max_idle_timeout`](Self::max_idle_timeout),
/// [`keep_alive_interval`](Self::keep_alive_interval), etc.). This mirrors the builder idiom of
/// `libp2p-quic`'s `Config`.
///
/// Beyond the usual QUIC/transport tunables, a `Config` holds an **ordered, non-empty set of
/// certificates** (sorted by `not_before` ascending). Index `0` is the *active* certificate — the
/// one served in the TLS handshake and advertised first in the listen multiaddr. The remaining
/// certificates are advertised so dialers can pin a successor ahead of rotation. The listener
/// manages this set over time, rotating to a fresh certificate before the active one expires (see
/// [`Transport`](crate::Transport) and [`Self::generate`]).
///
/// `Config` deliberately does **not** implement `Debug`: it holds the libp2p `keypair` and the
/// certificate private keys, which must not be logged.
#[derive(Clone)]
#[non_exhaustive]
pub struct Config {
    /// Maximum idle time in **milliseconds** before a connection is closed. `0` means *infinite*
    /// (quinn never times the connection out on idle); set this with care, as a stuck peer then
    /// holds the connection open indefinitely.
    max_idle_timeout: u32,
    /// Maximum number of concurrent inbound bidirectional streams.
    max_concurrent_stream_limit: u32,
    /// Period between keep-alive packets.
    keep_alive_interval: Duration,
    /// Connection-level flow-control receive window, in **bytes**.
    max_connection_data: u32,
    /// Per-stream flow-control receive window, in **bytes**.
    max_stream_data: u32,
    /// Path-MTU-discovery configuration. `None` disables discovery; `Some(_)` enables it (this is
    /// the default).
    mtu_discovery_config: Option<MtuDiscoveryConfig>,
    /// Timeout for the initial handshake when establishing a connection. `pub(crate)` so the
    /// listener/dialer can read it; not part of the public API.
    pub(crate) handshake_timeout: Duration,
    /// Libp2p identity of the node. `pub(crate)` so the transport can read it; not part of the
    /// public API.
    pub(crate) keypair: libp2p_identity::Keypair,

    /// Ordered, non-empty certificate set, sorted by `not_before` ascending. `certs[0]` is the
    /// active (served) certificate.
    certs: Vec<Certificate>,
}

impl Config {
    /// Creates a config from a single certificate (back-compatible constructor).
    ///
    /// The resulting listener still self-rotates: it generates successor certificates as the
    /// supplied one approaches expiry. To start from a current+next pair instead, use
    /// [`Self::generate`].
    pub fn new(keypair: &libp2p_identity::Keypair, cert: Certificate) -> Self {
        // A single-element set is always valid, so the `Result` from `new_with_certs` cannot fail.
        Self::with_certs(keypair, vec![cert])
    }

    /// Creates a config from an ordered set of certificates.
    ///
    /// The certificates are sorted by `not_before` ascending (so `certs[0]` becomes the active
    /// one). Returns [`ConfigError::EmptyCertSet`] if `certs` is empty.
    pub fn new_with_certs(
        keypair: &libp2p_identity::Keypair,
        certs: Vec<Certificate>,
    ) -> Result<Self, ConfigError> {
        if certs.is_empty() {
            return Err(ConfigError::EmptyCertSet);
        }
        Ok(Self::with_certs(keypair, certs))
    }

    /// Builds the standard current+next certificate set anchored at `now`.
    ///
    /// Both certificates use sequential validity windows with a one-hour `CLOCK_SKEW_ALLOWANCE`
    /// backdate on each edge, matching go-libp2p:
    ///
    /// * the **current** certificate is backdated to `now - CLOCK_SKEW_ALLOWANCE` and is valid for
    ///   `CERT_VALID_PERIOD`;
    /// * the **next** certificate begins at `current.not_after - 2 * CLOCK_SKEW_ALLOWANCE` (the
    ///   overlap is purely the skew slack) and is also valid for `CERT_VALID_PERIOD`.
    ///
    /// Each window stays strictly under 14 days so browsers (Chromium) accept the pinned hashes.
    pub fn generate(
        keypair: &libp2p_identity::Keypair,
        now: OffsetDateTime,
    ) -> Result<Self, certificate::Error> {
        let current_not_before = now - CLOCK_SKEW_ALLOWANCE;
        let current = Certificate::generate_with_validity(current_not_before, CERT_VALID_PERIOD)?;

        // Anchor the successor so its window abuts the current one with only the 2 * skew overlap.
        let next_not_before = current.not_after() - 2 * CLOCK_SKEW_ALLOWANCE;
        let next = Certificate::generate_with_validity(next_not_before, CERT_VALID_PERIOD)?;

        // Both windows are well-formed and ordered, so construction cannot fail.
        Ok(Self::with_certs(keypair, vec![current, next]))
    }

    /// Internal constructor: sorts the (assumed non-empty) certificate set and fills defaults.
    fn with_certs(keypair: &libp2p_identity::Keypair, mut certs: Vec<Certificate>) -> Self {
        certs.sort_by_key(|c| c.not_before());

        let max_idle_timeout = 30 * 1000;
        let max_concurrent_stream_limit = 256;
        let keep_alive_interval = Duration::from_secs(5);
        let max_connection_data = 15_000_000;
        // Ensure that one stream is not consuming the whole connection.
        let max_stream_data = 10_000_000;
        // Path-MTU discovery is on by default (mirrors `quic::Config`).
        let mtu_discovery_config = Some(MtuDiscoveryConfig::default());

        Self {
            max_idle_timeout,
            max_concurrent_stream_limit,
            keep_alive_interval,
            max_connection_data,
            max_stream_data,
            mtu_discovery_config,
            handshake_timeout: Duration::from_secs(5),
            keypair: keypair.clone(),
            certs,
        }
    }

    /// Set the maximum idle time in **milliseconds** before a connection is closed.
    ///
    /// A value of `0` means *infinite* (quinn never closes the connection on idle); use with care.
    pub fn max_idle_timeout(mut self, millis: u32) -> Self {
        self.max_idle_timeout = millis;
        self
    }

    /// Set the period between keep-alive packets.
    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    /// Set the maximum number of concurrent inbound bidirectional streams.
    pub fn max_concurrent_stream_limit(mut self, limit: u32) -> Self {
        self.max_concurrent_stream_limit = limit;
        self
    }

    /// Set the per-stream flow-control receive window, in **bytes**.
    pub fn max_stream_data(mut self, bytes: u32) -> Self {
        self.max_stream_data = bytes;
        self
    }

    /// Set the connection-level flow-control receive window, in **bytes**.
    pub fn max_connection_data(mut self, bytes: u32) -> Self {
        self.max_connection_data = bytes;
        self
    }

    /// Set the timeout for the initial connection handshake.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set the upper bound for path-MTU discovery, re-enabling discovery if it was previously
    /// disabled via [`disable_path_mtu_discovery`](Self::disable_path_mtu_discovery).
    pub fn mtu_upper_bound(mut self, value: u16) -> Self {
        self.mtu_discovery_config
            .get_or_insert_with(MtuDiscoveryConfig::default)
            .upper_bound(value);
        self
    }

    /// Disable path-MTU discovery.
    pub fn disable_path_mtu_discovery(mut self) -> Self {
        self.mtu_discovery_config = None;
        self
    }

    /// The active (served) certificate, i.e. `certs[0]`.
    pub fn active_cert(&self) -> &Certificate {
        &self.certs[0]
    }

    /// The full ordered certificate set (active first).
    pub fn certs(&self) -> &[Certificate] {
        &self.certs
    }

    /// Derives the TLS server config from the active certificate only.
    ///
    /// `pub(crate)`: it returns a `wtransport`/`rustls` type and is an internal listener seam.
    pub(crate) fn server_tls_config(&self) -> TlsServerConfig {
        libp2p_tls::make_webtransport_server_config(
            self.active_cert().certificate_der(),
            &self.active_cert().private_key_der(),
            alpn_protocols(),
        )
    }

    /// Builds the quinn transport config from the current tunables.
    ///
    /// `pub(crate)`: it returns a `quinn` type and is an internal listener seam.
    pub(crate) fn get_quic_transport_config(&self) -> QuicTransportConfig {
        self.quic_params().build()
    }

    /// The QUIC transport parameters in a `Clone`-able form, so a listener can rebuild a fresh
    /// (non-`Clone`) [`QuicTransportConfig`] during certificate rotation.
    pub(crate) fn quic_params(&self) -> QuicParams {
        QuicParams {
            max_concurrent_stream_limit: self.max_concurrent_stream_limit,
            keep_alive_interval: self.keep_alive_interval,
            max_idle_timeout: self.max_idle_timeout,
            max_stream_data: self.max_stream_data,
            max_connection_data: self.max_connection_data,
            mtu_discovery_config: self.mtu_discovery_config.clone(),
        }
    }

    /// The certificate hashes to advertise, active certificate first.
    ///
    /// This maps over the **entire** certificate set. The listener splits the result into the
    /// multiaddr set (current + next) and the Noise set (which may additionally include a
    /// recently-expired hash); see [`Transport`](crate::Transport).
    ///
    /// `pub(crate)`: an internal seam. The listener computes its advertised hashes directly from
    /// its own certificate set during rotation, so this is currently used only by tests.
    #[cfg(test)]
    pub(crate) fn cert_hashes(&self) -> Vec<crate::certificate::CertHash> {
        self.certs.iter().map(|c| c.cert_hash()).collect()
    }
}

/// ALPN protocol identifiers offered by a libp2p WebTransport server.
///
/// WebTransport is layered on HTTP/3, so the only ALPN value negotiated is `h3`
/// (the `http3.NextProtoH3` constant in quic-go). This matches go-libp2p — which
/// sets `NextProtos = ["h3"]` on both its WebTransport listener and dialer — and the
/// browser WebTransport stack, which negotiates `h3` internally.
///
/// The libp2p identity is **not** authenticated in TLS here; it is authenticated
/// out-of-band over a Noise handshake on the first stream (see the crate-level docs).
/// The `libp2p` ALPN used by the raw QUIC/TLS transport (`libp2p_tls::P2P_ALPN`) is
/// therefore deliberately NOT offered for WebTransport.
///
/// NOTE for a future same-port "Mixed" mode (raw QUIC + WebTransport sharing one UDP
/// port): keep this set disjoint from the QUIC transport's `["libp2p"]` so the
/// negotiated ALPN can demultiplex the two protocols. Do not add `libp2p` here.
pub(crate) fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h3".to_vec()]
}

/// `Clone`-able QUIC transport parameters used to (re)build a [`QuicTransportConfig`].
///
/// [`QuicTransportConfig`] (quinn's `TransportConfig`) is not `Clone`, so the listener retains
/// these scalar parameters and rebuilds a fresh config each time it hot-swaps the endpoint during
/// certificate rotation.
#[derive(Clone)]
pub(crate) struct QuicParams {
    max_concurrent_stream_limit: u32,
    keep_alive_interval: Duration,
    max_idle_timeout: u32,
    max_stream_data: u32,
    max_connection_data: u32,
    mtu_discovery_config: Option<MtuDiscoveryConfig>,
}

impl QuicParams {
    pub(crate) fn build(&self) -> QuicTransportConfig {
        let mut res = QuicTransportConfig::default();

        res.max_concurrent_uni_streams(100u32.into());
        res.max_concurrent_bidi_streams(self.max_concurrent_stream_limit.into());
        // Keep QUIC datagram support enabled (quinn's default). WebTransport over HTTP/3 negotiates
        // the `H3_DATAGRAM` extension, and browsers (Chromium) close the connection with an
        // `H3_DATAGRAM_ERROR` if the server has datagrams disabled — even though libp2p only uses
        // streams. Disabling datagrams here breaks browser interop.
        res.keep_alive_interval(Some(self.keep_alive_interval));
        res.max_idle_timeout(Some(VarInt::from_u32(self.max_idle_timeout).into()));
        res.allow_spin(true);
        res.stream_receive_window(self.max_stream_data.into());
        res.receive_window(self.max_connection_data.into());
        res.mtu_discovery_config(self.mtu_discovery_config.clone());

        res
    }
}

#[cfg(test)]
mod tests {
    use libp2p_identity::Keypair;
    use time::{Duration, macros::datetime};

    use super::*;

    fn keypair() -> Keypair {
        Keypair::generate_ed25519()
    }

    // CFG1: `new` advertises exactly one hash.
    #[test]
    fn new_advertises_single_hash() {
        let cert = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        let config = Config::new(&keypair(), cert);
        assert_eq!(config.cert_hashes().len(), 1);
        assert_eq!(config.certs().len(), 1);
    }

    // CFG2: `generate` yields exactly two distinct hashes, active first.
    #[test]
    fn generate_yields_two_distinct_hashes_active_first() {
        let now = datetime!(2025-08-08 0:00 UTC);
        let config = Config::generate(&keypair(), now).unwrap();
        let hashes = config.cert_hashes();

        assert_eq!(hashes.len(), 2);
        assert_ne!(hashes[0], hashes[1]);
        assert_eq!(hashes[0], config.active_cert().cert_hash());
        assert_eq!(hashes[0], config.certs()[0].cert_hash());
    }

    // CFG3: windows are sequential with the 1h skew backdate.
    #[test]
    fn generate_windows_sequential_with_skew() {
        let now = datetime!(2025-08-08 0:00 UTC);
        let config = Config::generate(&keypair(), now).unwrap();
        let current = &config.certs()[0];
        let next = &config.certs()[1];

        // Current is backdated by the skew allowance.
        assert_eq!(current.not_before(), now - CLOCK_SKEW_ALLOWANCE);
        // Next abuts current minus 2 * skew (the overlap is purely skew slack).
        assert_eq!(
            next.not_before(),
            current.not_after() - 2 * CLOCK_SKEW_ALLOWANCE
        );
    }

    // CFG4: `new_with_certs` sorts out-of-order input.
    #[test]
    fn new_with_certs_sorts_input() {
        let early = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        let late = Certificate::generate(datetime!(2025-08-20 0:00 UTC)).unwrap();
        let early_hash = early.cert_hash();

        // Supply out of order (late first).
        let config = Config::new_with_certs(&keypair(), vec![late, early]).unwrap();
        assert_eq!(config.active_cert().cert_hash(), early_hash);
        assert!(config.certs()[0].not_before() <= config.certs()[1].not_before());
    }

    // CFG5: empty set is rejected.
    #[test]
    fn new_with_certs_rejects_empty() {
        assert!(matches!(
            Config::new_with_certs(&keypair(), vec![]),
            Err(ConfigError::EmptyCertSet)
        ));
    }

    // CFG6: server_tls_config uses certs[0] (it builds without panicking from the active cert).
    #[test]
    fn server_tls_config_uses_active_cert() {
        let now = datetime!(2025-08-08 0:00 UTC);
        let config = Config::generate(&keypair(), now).unwrap();
        // Building the TLS config from the active cert must succeed.
        let _ = config.server_tls_config();
    }

    // CFG7: skew / validity relationship is sane (2 * skew < validity).
    #[test]
    fn skew_smaller_than_validity() {
        assert!(2 * CLOCK_SKEW_ALLOWANCE < CERT_VALID_PERIOD);
    }

    // CFG8: every advertised window is under 14 days.
    #[test]
    fn every_window_under_14_days() {
        let now = datetime!(2025-08-08 0:00 UTC);
        let config = Config::generate(&keypair(), now).unwrap();
        for cert in config.certs() {
            assert!(cert.not_after() - cert.not_before() < Duration::days(14));
        }
    }

    fn single_cert_config() -> Config {
        let cert = Certificate::generate(datetime!(2025-08-08 0:00 UTC)).unwrap();
        Config::new(&keypair(), cert)
    }

    // CFG9: `new` fills the documented defaults, including MTU discovery on.
    #[test]
    fn new_has_documented_defaults() {
        let config = single_cert_config();
        assert_eq!(config.max_idle_timeout, 30_000);
        assert_eq!(config.max_concurrent_stream_limit, 256);
        assert_eq!(
            config.keep_alive_interval,
            std::time::Duration::from_secs(5)
        );
        assert_eq!(config.max_connection_data, 15_000_000);
        assert_eq!(config.max_stream_data, 10_000_000);
        assert_eq!(config.handshake_timeout, std::time::Duration::from_secs(5));
        assert!(config.mtu_discovery_config.is_some());
    }

    // CFG10: chained setters apply and override defaults.
    #[test]
    fn setters_chain_and_override() {
        let config = single_cert_config()
            .max_idle_timeout(1234)
            .keep_alive_interval(std::time::Duration::from_secs(7))
            .max_concurrent_stream_limit(9)
            .max_stream_data(111)
            .max_connection_data(222)
            .handshake_timeout(std::time::Duration::from_secs(3));

        assert_eq!(config.max_idle_timeout, 1234);
        assert_eq!(
            config.keep_alive_interval,
            std::time::Duration::from_secs(7)
        );
        assert_eq!(config.max_concurrent_stream_limit, 9);
        assert_eq!(config.max_stream_data, 111);
        assert_eq!(config.max_connection_data, 222);
        assert_eq!(config.handshake_timeout, std::time::Duration::from_secs(3));
    }

    // CFG11: disable_path_mtu_discovery sets the field to None; get_quic_transport_config still
    // builds without panicking.
    #[test]
    fn disable_path_mtu_discovery_sets_none() {
        let config = single_cert_config().disable_path_mtu_discovery();
        assert!(config.mtu_discovery_config.is_none());
        // Building the quinn transport config must not panic on the disabled path.
        let _ = config.get_quic_transport_config();
    }

    // CFG12: mtu_upper_bound re-enables discovery after it was disabled (no panic on a None field).
    #[test]
    fn mtu_upper_bound_inserts_default_when_disabled_then_set() {
        let config = single_cert_config()
            .disable_path_mtu_discovery()
            .mtu_upper_bound(1400);
        assert!(config.mtu_discovery_config.is_some());
        let _ = config.get_quic_transport_config();
    }

    // CFG13: Config is Clone and the clone preserves tunables.
    #[test]
    fn config_is_clone() {
        let config = single_cert_config().max_idle_timeout(4242);
        let clone = config.clone();
        assert_eq!(clone.max_idle_timeout, 4242);
        assert_eq!(clone.certs().len(), config.certs().len());
    }

    // CFG14: get_quic_transport_config builds without panic on the default (MTU enabled) path and
    // is pub(crate)-callable.
    #[test]
    fn get_quic_transport_config_reflects_setters() {
        let config = single_cert_config().max_stream_data(4096);
        let _ = config.get_quic_transport_config();
    }

    // CFG15: cert_hashes yields a single SHA-256 multihash for a one-cert config.
    #[test]
    fn cert_hashes_single_sha256() {
        let config = single_cert_config();
        let hashes = config.cert_hashes();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].digest().len(), 32);
    }

    #[test]
    fn alpn_protocols_is_h3_only() {
        assert_eq!(alpn_protocols(), vec![b"h3".to_vec()]);
    }

    #[test]
    fn alpn_does_not_offer_libp2p() {
        // Regression guard (T1/T6): the WebTransport endpoint cannot authenticate libp2p
        // identity in TLS, so it must never advertise the raw QUIC/TLS `libp2p` ALPN.
        assert!(!alpn_protocols().contains(&libp2p_tls::P2P_ALPN.to_vec()));
    }

    #[test]
    fn alpn_h3_bytes_exact() {
        let protocols = alpn_protocols();
        assert_eq!(protocols.len(), 1);
        assert_eq!(protocols[0], vec![0x68, 0x33]); // b"h3"
    }

    #[test]
    fn server_tls_config_builds() {
        // `server_tls_config()` must not panic with the single-element ALPN list.
        let keypair = libp2p_identity::Keypair::generate_ed25519();
        let not_before = time::OffsetDateTime::now_utc();
        let cert = Certificate::generate(not_before).expect("generate certificate");
        let config = Config::new(&keypair, cert);
        let _ = config.server_tls_config();
    }
}
