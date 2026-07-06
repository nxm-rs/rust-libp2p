## 0.1.0

- Initial release: a shared QUIC endpoint holder, the analogue of go-libp2p's `quicreuse`.
  `SharedQuicEndpoint` owns one `quinn::Endpoint` (one UDP socket, one port) and, per registered
  ALPN, a complete `Arc<quinn::ServerConfig>` carrying that protocol's own certificate and
  client-auth verifier. The accept loop peeks the ALPN offered in the client's Initial packet
  (best-effort accessor on `quinn::Incoming`), accepts the connection with the matching config
  via `quinn::Incoming::accept_with`, and hands the resulting `quinn::Connecting` to the channel
  registered for that ALPN. An absent or unknown offered ALPN falls back to the default
  (first-registered) config; unroutable connections are refused. `dial_quic` dials raw QUIC from
  the shared socket so co-located transports reuse the same port for outbound connections.

  Design notes:
  - Delivered as a standalone crate rather than a module inside `libp2p-quic`: the holder is a
    pure quinn-level object with no dependency on `libp2p-core`, it is shared by more than one
    transport, and it mirrors go-libp2p's `quicreuse` package boundary.
  - The ALPN peek is a routing hint only. Each registered `ServerConfig` independently enforces
    its own ALPN allowlist and verifier, so a wrong or empty peek can only fail a handshake,
    never downgrade authentication.
  - The peek runs inside quinn after its retry and address-validation handling, and the holder
    only reads it when more than one ALPN is registered.
  - The accept path is panic-free and applies no backpressure: a full or closed sink drops that
    connection rather than stalling accept for the other protocols.
  - Tokio-only for now, matching the runtimes supported by `libp2p-quic`.

  Additional surface for transports built on the holder: `try_clone_socket` clones the
  underlying UDP socket so a co-located protocol can send raw datagrams from the shared port
  (as QUIC hole punching does), and `close` shuts the endpoint down for holders that are
  privately owned by a single protocol.
