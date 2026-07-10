## Unreleased

- Add single-port integration tests proving the co-listening model end to end: one UDP socket
  serves both `/quic-v1` and `/webtransport`, a plain-QUIC dialer and a WebTransport dialer both
  connect and observe the identical local port, and the ALPN demux is deterministic (an `h3`
  dial completes the WebTransport session, a `libp2p` dial completes the QUIC handshake, with no
  crossover between the two listeners). The auth-preservation guard asserts that the plain-QUIC
  inbound path on the shared listener keeps libp2p mutual TLS authentication: a QUIC client
  presenting no client certificate, or a non-libp2p one, is rejected by the handshake, while a
  proper libp2p client succeeds on the same listener. A go-libp2p interop smoke (ignored by
  default, it needs the external echo server) dials go from a mixed single-port node; the
  WebTransport handshake bytes on the wire are unchanged by the shared-socket refactor.

- Source QUIC connections from a `libp2p-quicreuse` endpoint holder so WebTransport can co-listen
  with plain QUIC on one UDP port, demultiplexed by the negotiated ALPN. `listen_on` registers the
  `h3` ALPN together with the WebTransport server config (no client auth, certhash-pinned
  certificate) on the holder and receives the routed inbound connections; the WebTransport session
  is then driven over each routed connection by `wtransport` acting purely as the protocol engine
  (it no longer owns a socket or endpoint). `Transport::with_shared_endpoint` accepts an externally
  shared `SharedQuicEndpoint`, used for listeners and reuse-dials whose address matches it; a
  transport built with `Transport::new` keeps its previous behaviour through a private holder.
  Dials go through the holder's shared socket and keep pinning the presented certificate by the
  SHA-256 hashes from the multiaddr `/certhash` components. Certificate rotation still lives in
  this transport; the rotated server config is swapped in the holder's config map.

- Correctness & safety fixes.

  - **`Certificate::parse` is now panic-free and bounds its allocations.** The four `.unwrap()`s
    are replaced by error returns and each length-prefixed field is checked against a 64 KiB cap
    *before* allocating, so an attacker-supplied length prefix can no longer drive a large
    allocation. The encoding is now canonical (trailing bytes are rejected). A successful parse is
    still *not* a semantic validation of the certificate (the timestamp ordering and DER structure
    are not checked).
  - **Stream reads no longer depend on the send-half close state.** `Stream::poll_read` delegates
    solely to the recv half; quinn reports FIN (`Ok(0)`) and reset (`Err`) on the recv half itself.
    Previously a closed send half could fabricate a clean read EOF. This is a robustness/hygiene
    fix (the conflation was not remotely triggerable).
  - **`listen_on` no longer panics on socket-descriptor exhaustion.** The dead `try_clone().unwrap()`
    is removed; the single bound socket is handed to the endpoint and the listen address is read back
    from `Endpoint::local_addr()`. The per-connection `socket_addr()` accessor is now infallible
    (the bound address is cached).
  - **`listen_on` validates an optional `/p2p/<peer-id>`.** An absent or local-matching peer id is
    accepted (unchanged for the common case); a foreign peer id, or an address carrying more than
    one `/p2p/`, is now rejected with `MultiaddrNotSupported` (combinator-friendly). This is a *new*
    policy — neither the QUIC nor TCP transports validate the listen-side `/p2p/`.

  API notes (crate is unreleased on a feature branch; forward-looking only):
  - Both `Error` enums (`crate::Error` and `certificate::Error`) are now `#[non_exhaustive]`.
  - `certificate::Error` gains `InvalidLength`, `InvalidPrivateKey`, `InvalidTimestamp`, and
    `TrailingData` variants, plus `Display` and `std::error::Error` impls.
  - `Certificate::parse`'s signature is unchanged; only its failure modes are (it now returns the
    new error variants instead of panicking).
  - `Listener::new`'s signature changed (`UdpSocket` → `SocketAddr`) but the type is module-private,
    so there is no external API impact.
  - No wire/multiaddr format change. `poll_read` only *fixes* read behaviour; `listen_on` only newly
    *rejects* foreign-`/p2p/` (and doubled-`/p2p/`) listen addresses.

- Public-API stabilization ahead of the initial publish (crate is unreleased; pre-release
  reshaping, not released breaking changes):

  - **`Config` is now a builder.** All fields are private and the type is `#[non_exhaustive]` and
    `Clone`. Construct via `Config::new` / `new_with_certs` / `generate`, then tune with chained
    `mut self -> Self` setters: `max_idle_timeout` (ms; `0` = infinite), `keep_alive_interval`,
    `max_concurrent_stream_limit`, `max_stream_data` (bytes), `max_connection_data` (bytes),
    `handshake_timeout`, `mtu_upper_bound`, and `disable_path_mtu_discovery`. Path-MTU discovery is
    on by default (`mtu_discovery_config` is now an `Option`, internally). `Config` deliberately
    has no `Debug` impl (it holds the keypair and certificate private keys).
  - **`Certificate` accessors renamed**: `get_certificate_der` → `certificate_der`,
    `get_private_key_der` → `private_key_der`.
  - **`certificate::Error` is now a `thiserror` enum** (`#[non_exhaustive]`) with an
    `UnsupportedVersion(u8)` variant, and is re-exported at the crate root as `CertificateError`.
  - **Versioned certificate serialization.** `Certificate::to_bytes` now writes a leading version
    byte (`SERIALIZATION_VERSION = 1`, also re-exported); `parse` validates it first and rejects a
    blob from an incompatible build with `UnsupportedVersion`. `parse` additionally rejects a
    mis-ordered validity window (`not_after <= not_before`). **Serialized certificates from before
    this change are no longer parseable — regenerate them.** The blob carries the cleartext private
    key; store it `0600`.
  - The internal accessors `server_tls_config`, `get_quic_transport_config`, and `cert_hashes` are
    no longer `pub` (demoted to crate-internal); they returned `wtransport`/`quinn` types and had no
    external callers.

- Spec / idiom polish:

  - Offer only the `h3` ALPN on the server (was `["libp2p", "h3"]`). WebTransport runs over HTTP/3
    and authenticates libp2p identity over Noise, not in TLS, so the raw QUIC/TLS `libp2p` ALPN is
    no longer advertised. This matches go-libp2p and the browser WebTransport stack. See [#5].
  - Honour `DialOpts` in `Transport::dial`. A coordinated hole-punch
    (`role: Endpoint::Listener, port_use: PortUse::New`) now fails synchronously with the new
    `Error::HolePunchingUnsupported` variant instead of silently dialing from a fresh socket;
    `PortUse::Reuse` is downgraded best-effort to a fresh ephemeral socket and logged at `trace`
    (`wtransport`'s client endpoint cannot reuse the listener's socket). See [#5].
  - `Error` is now `#[non_exhaustive]`.
  - Add the standard MIT license header to all source files. See [#5].

[#5]: https://github.com/nxm-rs/rust-libp2p/issues/5

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
