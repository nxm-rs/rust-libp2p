# Native WebTransport transport for libp2p

This crate provides a native (non-browser) [WebTransport] transport for rust-libp2p, built on
[`wtransport`] (WebTransport over HTTP/3 / QUIC). It is the native counterpart to
[`libp2p-webtransport-websys`], enabling WebTransport interoperability between native nodes and
WASM/browser nodes.

Capabilities:

- **Listen** for incoming WebTransport sessions (so a browser/WASM node can dial a native node).
  The listen multiaddr may optionally end with `/p2p/<peer-id>`, which must match the local peer
  id (a foreign peer id is rejected); the `/certhash` components are managed by the listener and
  must not be supplied.
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

## Configuring the transport

`Config` has private fields and is `#[non_exhaustive]`. Construct it with `Config::new` (single
certificate), `Config::new_with_certs`, or `Config::generate` (current+next pair), then tune it with
the chained `mut self -> Self` setters (mirroring `libp2p-quic`'s `Config`):

```rust,no_run
use std::time::Duration;
use libp2p_identity::Keypair;
use libp2p_webtransport::{Config, Certificate};
use time::OffsetDateTime;

let keypair = Keypair::generate_ed25519();
let cert = Certificate::generate(OffsetDateTime::now_utc()).unwrap();
let config = Config::new(&keypair, cert)
    .max_idle_timeout(30_000) // milliseconds; 0 means "infinite" — use with care
    .keep_alive_interval(Duration::from_secs(5))
    .max_concurrent_stream_limit(256)
    .disable_path_mtu_discovery();
```

`Config` deliberately has no `Debug` impl: it holds the libp2p keypair and the certificate private
keys, which must not be logged.

## Persisting the certificate

`Certificate::to_bytes` / `Certificate::parse` serialize and restore a certificate (with its private
key and validity window) across restarts. The format begins with a single version byte
(`SERIALIZATION_VERSION`); `parse` is total (never panics, bounds its allocations) and rejects a
blob from an incompatible build with `CertificateError::UnsupportedVersion`. Certificates serialized
before this versioning was introduced are not parseable and must be regenerated.

> **Security:** the serialized blob contains the private key **in the clear** and is not
> authenticated (the version byte is a compatibility discriminator, not integrity protection). Store
> it with filesystem-level confidentiality — mode `0600` or a secret store.

## License

Licensed under MIT.

[WebTransport]: https://www.w3.org/TR/webtransport/
[`wtransport`]: https://docs.rs/wtransport
[`libp2p-webtransport-websys`]: https://docs.rs/libp2p-webtransport-websys
[spec]: https://github.com/libp2p/specs/blob/master/webtransport/README.md
