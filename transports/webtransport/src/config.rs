use std::time::Duration;

use quinn::{MtuDiscoveryConfig, VarInt};
use time::OffsetDateTime;
use wtransport::config::{QuicTransportConfig, TlsServerConfig};

use crate::certificate::{self, CERT_VALID_PERIOD, CLOCK_SKEW_ALLOWANCE, CertHash, Certificate};

/// Error returned when constructing a [`Config`] with an invalid certificate set.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A [`Config`] must hold at least one certificate; an empty set was supplied.
    #[error("a WebTransport config requires at least one certificate")]
    EmptyCertSet,
}

/// Configuration for the native WebTransport [`Transport`](crate::Transport).
///
/// Beyond the usual QUIC/transport tunables, a `Config` holds an **ordered, non-empty set of
/// certificates** (`certs`, sorted by `not_before` ascending). Index `0` is the *active*
/// certificate — the one served in the TLS handshake and advertised first in the listen multiaddr.
/// The remaining certificates are advertised so dialers can pin a successor ahead of rotation. The
/// listener manages this set over time, rotating to a fresh certificate before the active one
/// expires (see [`Transport`](crate::Transport) and [`Self::generate`]).
pub struct Config {
    pub max_idle_timeout: u32,
    pub max_concurrent_stream_limit: u32,
    pub keep_alive_interval: Duration,
    pub max_connection_data: u32,
    pub max_stream_data: u32,
    pub mtu_discovery_config: MtuDiscoveryConfig,
    /// Timeout for the initial handshake when establishing a connection.
    /// The actual timeout is the minimum of this and the [`Config::max_idle_timeout`].
    pub handshake_timeout: Duration,
    /// Libp2p identity of the node.
    pub keypair: libp2p_identity::Keypair,

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
        let mtu_discovery_config = Default::default();

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

    /// The active (served) certificate, i.e. `certs[0]`.
    pub fn active_cert(&self) -> &Certificate {
        &self.certs[0]
    }

    /// The full ordered certificate set (active first).
    pub fn certs(&self) -> &[Certificate] {
        &self.certs
    }

    /// Derives the TLS server config from the active certificate only.
    pub fn server_tls_config(&self) -> TlsServerConfig {
        libp2p_tls::make_webtransport_server_config(
            self.active_cert().get_certificate_der(),
            &self.active_cert().get_private_key_der(),
            alpn_protocols(),
        )
    }

    pub fn get_quic_transport_config(&self) -> QuicTransportConfig {
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
    pub fn cert_hashes(&self) -> Vec<CertHash> {
        self.certs.iter().map(|c| c.cert_hash()).collect()
    }
}

pub(crate) fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![libp2p_tls::P2P_ALPN.to_vec(), b"h3".to_vec()]
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
    mtu_discovery_config: MtuDiscoveryConfig,
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
        res.mtu_discovery_config(Some(self.mtu_discovery_config.clone()));

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
}
