## 0.1.0 (unreleased)

- Offer only the `h3` ALPN on the server (was `["libp2p", "h3"]`). WebTransport runs over HTTP/3
  and authenticates libp2p identity over Noise, not in TLS, so the raw QUIC/TLS `libp2p` ALPN is no
  longer advertised. This matches go-libp2p and the browser WebTransport stack. See [#5].
- Honour `DialOpts` in `Transport::dial`. A coordinated hole-punch
  (`role: Endpoint::Listener, port_use: PortUse::New`) now fails synchronously with the new
  `Error::HolePunchingUnsupported` variant instead of silently dialing from a fresh socket;
  `PortUse::Reuse` is downgraded best-effort to a fresh ephemeral socket and logged at `trace`
  (`wtransport`'s client endpoint cannot reuse the listener's socket). See [#5].
- `Error` is now `#[non_exhaustive]`.
- Add the standard MIT license header to all source files. See [#5].

[#5]: https://github.com/nxm-rs/rust-libp2p/issues/5

## 0.1.0

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
