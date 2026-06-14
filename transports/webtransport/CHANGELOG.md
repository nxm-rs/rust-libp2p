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
