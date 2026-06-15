## Unreleased

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
