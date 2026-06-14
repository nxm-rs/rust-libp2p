# Native WebTransport transport for libp2p

This crate provides a native (non-browser) [WebTransport] transport for rust-libp2p, built on
[`wtransport`] (WebTransport over HTTP/3 / QUIC). It is the native counterpart to
[`libp2p-webtransport-websys`], enabling WebTransport interoperability between native nodes and
WASM/browser nodes.

Capabilities:

- **Listen** for incoming WebTransport sessions (so a browser/WASM node can dial a native node).
- **Dial** other WebTransport endpoints (native → native).
- Either peer of an established connection can open new bidirectional streams.

Authentication follows the [libp2p WebTransport specification][spec]: a short-lived self-signed
certificate whose SHA-256 hash is published in the multiaddr (`/certhash`), plus a Noise handshake
over the first stream that authenticates the libp2p `PeerId` and binds the certificate hashes to
it.

Example listen multiaddr:

```text
/ip4/127.0.0.1/udp/4433/quic-v1/webtransport/certhash/uEi...
```

## License

Licensed under MIT.

[WebTransport]: https://www.w3.org/TR/webtransport/
[`wtransport`]: https://docs.rs/wtransport
[`libp2p-webtransport-websys`]: https://docs.rs/libp2p-webtransport-websys
[spec]: https://github.com/libp2p/specs/blob/master/webtransport/README.md
