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
use wtransport::config::{QuicTransportConfig, TlsServerConfig};

use crate::certificate::{CertHash, Certificate};

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

    cert: Certificate,
}

impl Config {
    pub fn new(keypair: &libp2p_identity::Keypair, cert: Certificate) -> Self {
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
            cert,
        }
    }

    pub fn server_tls_config(&self) -> TlsServerConfig {
        libp2p_tls::make_webtransport_server_config(
            self.cert.get_certificate_der(),
            self.cert.get_private_key_der(),
            alpn_protocols(),
        )
    }

    pub fn get_quic_transport_config(&self) -> QuicTransportConfig {
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

    pub fn cert_hashes(&self) -> Vec<CertHash> {
        vec![self.cert.cert_hash()]
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
fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h3".to_vec()]
}

#[cfg(test)]
mod tests {
    use super::*;

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
