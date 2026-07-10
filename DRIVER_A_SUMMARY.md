# DRIVER A — WebTransport NAT-hole-punching via a shared QUIC endpoint (wtransport-based)

Branch: `feat/wt-hp-wtransport` (based on `feat/native-webtransport`).
Fork: `/code/nxm/wtransport-fork` (the `mfw78/wtransport` fork, checked out at the pinned
rev `8ebdde11` and extended; workspace `Cargo.toml` is repointed to it by `path`).

## TL;DR

The fatal limitation the base branch documented — *"`wtransport`'s client `Endpoint` always binds
its OWN fresh UDP socket, so it cannot dial from the listener's socket"* — has been removed. The
key realisation is that **both `wtransport` (quinn 0.11.6) and `libp2p-quic` (quinn 0.11.9) sit on
the same semver-compatible `quinn` 0.11.x**, so a single `quinn::Endpoint`/`quinn::Connection` type
flows between them.

WebTransport dials now:

1. select a `quinn::Endpoint` from the `(role, port_use)` tuple, **mirroring `libp2p-quic`** —
   reusing an existing listener's endpoint (its UDP socket) for `PortUse::Reuse` and for the
   `(Listener, New)` hole-punch case;
2. establish the raw QUIC connection themselves over that endpoint (`endpoint.connect_with`);
3. drive `wtransport`'s WebTransport/H3 client handshake **over that externally-owned
   `quinn::Connection`** via a new fork API, `wtransport::endpoint::connect_over_quic`.

Because the punch machinery in `libp2p-quic` operates on the raw listener socket and a WT dial now
reuses that same socket, **hole punching falls out** exactly as the task described. The
interop-tested handshake details (draft-02 header, certhash pinning, Noise-over-bidi, `h3` ALPN,
datagrams) are unchanged.

## What I implemented

### 1. wtransport fork API additions (`/code/nxm/wtransport-fork/wtransport/src/endpoint.rs`)

Two additions, both gated behind the existing `quinn` feature (so they only appear when the caller
opts into exposing `quinn` types), symmetric with the fork's pre-existing **server** hooks
`IncomingSessionFuture::with_quic_{incoming,connecting}`:

- **`pub async fn connect_over_quic<O: IntoConnectOptions>(quic_connection: quinn::Connection,
  options: O) -> Result<Connection, ConnectingError>`**
  The client-side counterpart to `with_quic_connecting`. It runs the H3 settings exchange, the
  CONNECT request, and WebTransport session negotiation over an **already-established**
  `quinn::Connection` (which must have negotiated the `h3` ALPN). Implemented by extracting the
  entire post-`endpoint.connect()` body of `Endpoint::<Client>::connect` into a shared private
  helper `connect_with_quic_connection(...)` and calling it from both `connect` (unchanged
  behaviour) and `connect_over_quic`. This is a pure refactor + new public entrypoint — zero
  behaviour change to the existing `connect` path.

- **`pub fn quic_endpoint(&self) -> &quinn::Endpoint`** on `Endpoint<Side>`.
  Exposes the inner `quinn::Endpoint` so the libp2p WebTransport listener (which builds its endpoint
  via `wtransport::Endpoint::server`) can dial a raw QUIC connection from the **same UDP socket it
  listens on**.

Fork diff: `wtransport/src/endpoint.rs`, +159/-78 (the bulk is the `connect` body moving into the
shared helper; the net new surface is ~70 lines: one free fn + one accessor + docs). Both fork
commits build standalone (`cargo check -p wtransport --features quinn` green) and the fork still
compiles with default features.

Fork commits:
- `a6bc5f4 feat(endpoint): add connect_over_quic client handshake over an external quinn::Connection`
- `49bba00 feat(endpoint): expose quic_endpoint() accessor on Endpoint<Side>`

### 2. libp2p-webtransport (`transports/webtransport/`)

- **`Cargo.toml`** (workspace root): repoint `wtransport`/`wtransport-proto` to the local fork by
  `path` (temporary; the consuming crate already enables `features = ["quinn","ring"]`).
- **`src/transport.rs`** (the substantive change, ~349 lines changed):
  - `Transport` gains a `dialer: HashMap<SocketFamily, quinn::Endpoint>` (a per-family cached
    ephemeral dialer endpoint), mirroring `GenTransport::dialer` in `libp2p-quic`.
  - `eligible_listener_endpoint(&self, &SocketAddr) -> Option<quinn::Endpoint>`: picks an open,
    same-family, loopback-compatible listener and returns a clone of its inner `quinn::Endpoint`
    (via the new `quic_endpoint()` accessor) — i.e. its UDP socket.
  - `dialer_endpoint(&mut self, SocketAddr, reuse: bool)`: builds (or, for `reuse`, caches+reuses) a
    fresh-socket client `quinn::Endpoint`.
  - `dial()` rewritten to select the endpoint by `(role, port_use)`:
    `Reuse | (Listener, New)` → listener's shared endpoint (else cached/fresh dialer);
    `(Dialer, New)` → throwaway fresh endpoint. The old synchronous `HolePunchingUnsupported`
    rejection and the `PortUse::Reuse` "downgrade to fresh socket" are gone.
  - `connect(endpoint, …)` now takes the chosen `quinn::Endpoint`, builds the dialer
    `quinn::ClientConfig` (cert-hash verifier + `h3` ALPN, obtained by reusing `wtransport`'s
    `ClientConfig` builder and extracting `.quic_config()`), dials via
    `endpoint.connect_with(client_config, addr, "l")`, then drives the WT handshake with
    `connect_over_quic`.
  - New helpers `new_client_endpoint` and `client_quic_config`.
- **`src/lib.rs`**: two new `Error` variants (`QuicConnect(#[from] quinn::ConnectError)`,
  `QuicConnection(#[from] quinn::ConnectionError)`); module + variant docs updated; the
  `HolePunchingUnsupported` variant is retained for API stability but documented as no-longer-returned.

Main commit: `91a49acb feat(webtransport): share QUIC UDP endpoint and inherit hole punching (DRIVER A)`.

## What works (tests + exact commands)

All commands wrapped as required:
`nix-shell -p cargo rustc pkg-config openssl protobuf cmake clang perl --run 'cd /code/nxm/rl-wt-wtransport && cargo <args>'`

### Compiles green
- `cargo check -p libp2p-webtransport --all-features` — Finished, clean.
- `cargo check -p libp2p-quic --all-features` — Finished, clean (the repoint does not disturb the
  QUIC transport).
- `cargo clippy -p libp2p-webtransport --all-targets` — no warnings for `libp2p-webtransport`.

### NATIVE↔NATIVE WebTransport over the shared-endpoint path — PASSES
`cargo test -p libp2p-webtransport --test smoke`
```
running 11 tests
test listener_reuse_dial_ping_pong ... ok          <-- NEW: (Listener, Reuse) = DCUtR scenario
test native_to_native_ping_pong ... ok             <-- now runs over connect_over_quic
test native_to_native_with_custom_config ... ok
test native_to_native_with_serialized_cert ... ok
test generate_config_ping_pong ... ok
test dial_pinning_only_active_hash ... ok
test dial_pinning_both_hashes_reversed_order ... ok
test dial_pinning_only_next_hash_fails_cleanly ... ok
test dial_stale_hash_fails_cleanly ... ok
test native_recv_reset_is_error ... ok
test native_half_closed_read_after_send_close ... ok
test result: ok. 11 passed; 0 failed; 0 ignored; ...
```
Every existing native↔native echo + cert-pinning test now exercises the new dial path (raw QUIC over
a libp2p-webtransport-owned `quinn::Endpoint`, WT handshake via `connect_over_quic`), and the new
`listener_reuse_dial_ping_pong` proves a `(Listener, Reuse)` dial — exactly what DCUtR's
`override_role()` emits — completes the full handshake + stream echo end to end.

### WebTransport dial REUSES the listener's UDP socket/port (hole-punch prerequisite) — PASSES
`cargo test -p libp2p-webtransport --lib`
```
test transport::test::reuse_dial_uses_listener_socket ... ok
test transport::test::holepunch_dial_uses_listener_socket ... ok
test transport::test::reuse_dial_without_listener_caches_dialer_endpoint ... ok
...
test result: ok. 77 passed; 0 failed; 0 ignored; ...
```
- `reuse_dial_uses_listener_socket`: drives a `Transport` to a bound listener, then asserts the
  endpoint selected for a loopback `PortUse::Reuse` dial has `local_addr().port() == listener.port()`
  — i.e. the dial reuses the listener's UDP socket.
- `holepunch_dial_uses_listener_socket`: same assertion for the `(Listener, New)` path, plus that
  the full `dial()` returns a dial future (no `HolePunchingUnsupported`).
- `reuse_dial_without_listener_caches_dialer_endpoint`: a reuse dial without a listener reuses one
  cached ephemeral socket across calls, while a `New` dial gets a fresh one.

The four pre-existing `(role, port_use)` matrix unit tests were updated: they now run under
`#[tokio::test]` (selecting an endpoint needs a Tokio reactor) and `dial_holepunch_new_port_rejected`
became `dial_holepunch_new_port_now_supported`.

Full crate run: `cargo test -p libp2p-webtransport` → 77 lib + 11 smoke + 2 doctests pass; the
`interop_go` test remains `ignored` (requires an external go-libp2p peer; not run here).

## What is stubbed / incomplete / not done — and why

1. **Listen-side single-socket ALPN demux is NOT implemented.** The task's go-libp2p `quicreuse`
   parity goal is *one* UDP socket per port carrying BOTH ALPNs (`libp2p` for QUIC, `h3` for WT),
   demuxed after the quinn handshake. I did **not** build that. Today the WT listener socket offers
   only `h3` and the QUIC listener socket only `libp2p`; they are separate sockets owned by separate
   `Transport` impls. Implementing a truly shared *listener* requires a `quicreuse`-style endpoint
   registry owned by neither transport alone, because `libp2p-quic`'s `GenTransport` owns its
   `quinn::Endpoint`s privately (`Listener.endpoint`, `dialer`) with no API to share them. That is a
   sizeable, upstream-divergent change to `libp2p-quic` and was out of proportion to the
   "least-invasive" directive. **Crucially, this does not block hole punching**: hole punching is a
   *dial-side* socket-reuse problem (dial from the listener's 4-tuple), and that is fully solved on
   the WT side. The demux note already in `config::alpn_protocols()` (keep `h3` disjoint from
   `libp2p`) remains the right groundwork for a future Mixed mode.

2. **No live DCUtR end-to-end test.** I prove the *prerequisite* (socket reuse) deterministically via
   unit tests and the `(Listener, Reuse)` echo test, but I did not stand up a full relay + DCUtR
   simultaneous-connect harness. The minimum bar ("socket-reuse evidence") is met and exceeded; the
   stretch DCUtR harness is not done.

3. **go-libp2p interop (stretch): not run.** The existing `interop_go` test is `#[ignore]`d and needs
   an external peer. The dial-side change preserves the exact handshake bytes (same `connect_over_quic`
   body, same draft-02 header, same `h3` ALPN, same cert pinning), so interop is *expected* to hold,
   but it is unverified here.

4. **Cross-family / unspecified-bind reuse** uses the same loopback-aware eligibility as
   `libp2p-quic`'s `eligible_listener`; multi-interface unspecified binds pick the first eligible
   listener (deterministic-enough for tests, matching quic's intent) rather than hashing — a minor
   simplification, not a correctness gap for the hole-punch use case.

## Lines of code / files touched

- Fork (`wtransport-fork`): 1 file, `wtransport/src/endpoint.rs` (+159/-78; net new surface ~70 lines).
- libp2p-webtransport: 4 files — `Cargo.toml` (repoint), `src/transport.rs` (~349 lines changed, the
  core), `src/lib.rs` (+41/-… docs + 2 error variants), `tests/smoke.rs` (+94, one new e2e test).

## Honest self-assessment

**Idiomaticity: good (dial side).** The dial path is a near-mirror of `libp2p-quic`'s
`GenTransport::dial` — same `(role, port_use)` match shape, same per-family dialer cache, same
"reuse listener endpoint" selection. The fork API (`connect_over_quic`) is symmetric with the
fork's own `with_quic_connecting` and gated behind the same `quinn` feature, so it reads as a natural
extension rather than a hack. Reusing `wtransport`'s `ClientConfig` builder to obtain the
cert-hash-pinning + `h3`-ALPN `quinn::ClientConfig` (instead of re-deriving the rustls verifier)
keeps the interop-critical TLS config single-sourced.

**Maintainability: medium.** The split between a WT-owned dial endpoint and a (future) shared
listener is a seam that a reader must understand; it is documented in the module docs and the `dial`
doc-comment. The retained-but-dead `HolePunchingUnsupported` variant is mild cruft kept for API
stability.

**Upstream-divergence / fork-maintenance burden: this is the real cost.** The approach hard-depends
on two fork-only APIs. The `path` repoint is a temporary local-machine pin and **must** be replaced
before this is shareable (push the two commits to the fork repo and pin by rev again, as the base
branch's comment already anticipated). `connect_over_quic` and `quic_endpoint()` are clean, small,
and plausibly upstreamable to `BiagioFesta/wtransport` (they mirror APIs the fork author already
added), which would eventually retire the fork divergence — but until then, every `wtransport`
rebase carries these two patches plus the existing pseudo-header fix. The deeper architectural debt
(a `quicreuse`-style shared listener) is deferred entirely and would be the larger follow-up.
