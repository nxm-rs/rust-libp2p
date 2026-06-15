## 0.1.0

- Certificate rotation (two-certificate scheme).

  Listeners now manage an **ordered set of certificates** and rotate automatically before the
  active certificate expires, so a listener no longer goes dead at the ~2-week certificate-validity
  boundary. Following the spec and go-libp2p, certificates use **sequential validity windows with a
  one-hour clock-skew backdate on each edge** (served validity `= certValidity - 2h`, kept under 14
  days for browser interop). A listener advertises **two** `/certhash` components in its multiaddr
  (current + next) and reports **up to three** over Noise (additionally a recently-expired one, per
  the spec SHOULD). On rotation the endpoint TLS config is hot-swapped without dropping live
  connections and the listen address is re-published (an `AddressExpired` followed by a
  `NewAddress`).

  Additive API (no breaking change — `Config::new` is preserved):
  - `Config::generate(&keypair, now)` — build a current+next certificate set;
  - `Config::new_with_certs(&keypair, certs)` — build from an ordered set (`Err(ConfigError)` on an
    empty set);
  - `Config::{active_cert, certs}` accessors;
  - `Certificate::{not_before, not_after}` accessors and `Certificate::generate_with_validity`;
  - `ConfigError`, and an `Error::Config` variant.

  Behavior change: a single-certificate `Config` (via `Config::new`) now self-rotates, and listen
  multiaddrs now carry **two** `/certhash` components (their order is not significant to dialers).
  The wire/multiaddr format is otherwise unchanged. The private key is now held in a zeroizing
  buffer and wiped on drop.

- Initial release of the native (non-browser) WebTransport transport.

  Forward-ported from the closed upstream PR [#5701] (which targeted `wtransport` 0.5 on a stale
  `master`) onto current `master`, updated to `wtransport` 0.7 / `quinn` 0.11, and extended with
  native **dialing** support: the original PR was listen-only, this implementation can both listen
  and dial and implements `StreamMuxer::poll_outbound`, so a native node can dial another native
  node and either peer can open streams.

  Verified interoperable in both directions with **go-libp2p** WebTransport and with the browser
  [`libp2p-webtransport-websys`] transport in real Chromium (a `wasm32` libp2p node dialing this
  native transport). Required fixes over the original PR for spec/ecosystem compatibility:
  - generate a **plain** self-signed ECDSA P-256 certificate (no libp2p X.509 extension) with a
    Subject Alternative Name and a sub-14-day validity window — identity is authenticated over
    Noise and the certificate is pinned by its SHA-256 hash;
  - keep **QUIC datagram support enabled** (browsers close the session with `H3_DATAGRAM_ERROR`
    otherwise);
  - send the `Sec-Webtransport-Http3-Draft02` header when dialing (required by go-libp2p).

[#5701]: https://github.com/libp2p/rust-libp2p/pull/5701
[`libp2p-webtransport-websys`]: https://crates.io/crates/libp2p-webtransport-websys
