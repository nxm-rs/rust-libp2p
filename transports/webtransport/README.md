# Native WebTransport transport for libp2p

This crate provides a native (non-browser) [WebTransport] transport for rust-libp2p, built on
[`wtransport`] (WebTransport over HTTP/3 / QUIC). It is the native counterpart to
[`libp2p-webtransport-websys`], enabling WebTransport interoperability between native nodes and
WASM/browser nodes.

Capabilities:

- **Listen** for incoming WebTransport sessions (so a browser/WASM node can dial a native node).
- **Dial** other WebTransport endpoints (native → native).
- Either peer of an established connection can open new bidirectional streams.
- **Automatic certificate rotation**: listeners rotate to a fresh certificate before the active one
  expires, hot-swapping the endpoint TLS config without dropping live connections.

Authentication follows the [libp2p WebTransport specification][spec]: a short-lived self-signed
certificate whose SHA-256 hash is published in the multiaddr (`/certhash`), plus a Noise handshake
over the first stream that authenticates the libp2p `PeerId` and binds the certificate hashes to
it.

## Certificate management

The self-signed certificate is short-lived (under 14 days — the ceiling browsers enforce for
hash-pinned certificates), so a listener cannot serve a single fixed certificate indefinitely.
Build the listener config with `Config::generate`, which produces a **current** (served) plus a
**next** (advertised) certificate using sequential validity windows with a one-hour clock-skew
backdate on each edge (served validity `= certValidity - 2h`). The listener:

- advertises **two** `/certhash` components in its multiaddr (current + next), and reports up to
  three over Noise (additionally a recently-expired hash, per the spec);
- generates a successor and hot-swaps the endpoint TLS config before the active certificate expires,
  without dropping live connections;
- re-publishes its listen address on rotation (an `AddressExpired` followed by a `NewAddress`).

A single-certificate `Config::new` config still self-rotates. The order of the two `/certhash`
components in a multiaddr is **not** significant to dialers (they pin both; the Noise check is an
order-insensitive subset check).

Example listen multiaddr (two certificate hashes):

```text
/ip4/127.0.0.1/udp/4433/quic-v1/webtransport/certhash/uEi.../certhash/uEi...
```

## License

Licensed under MIT.

[WebTransport]: https://www.w3.org/TR/webtransport/
[`wtransport`]: https://docs.rs/wtransport
[`libp2p-webtransport-websys`]: https://docs.rs/libp2p-webtransport-websys
[spec]: https://github.com/libp2p/specs/blob/master/webtransport/README.md
