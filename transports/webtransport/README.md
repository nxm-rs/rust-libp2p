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

## Limitations

- **No DCUtR hole punching.** A coordinated hole-punch dial
  (`DialOpts { role: Endpoint::Listener, port_use: PortUse::New }`) fails with
  `Error::HolePunchingUnsupported`: `wtransport`'s client endpoint always binds a fresh socket and
  cannot dial from the listener's socket.
- **`PortUse::Reuse` is not honoured.** Ordinary dials always bind a fresh ephemeral socket; the
  reuse request is downgraded best-effort and logged at `trace`.

Both stem from the `wtransport` API, which only exposes `connect` on a client endpoint.

## License

Licensed under MIT.

[WebTransport]: https://www.w3.org/TR/webtransport/
[`wtransport`]: https://docs.rs/wtransport
[`libp2p-webtransport-websys`]: https://docs.rs/libp2p-webtransport-websys
[spec]: https://github.com/libp2p/specs/blob/master/webtransport/README.md
