# libp2p-timer

One timer backend for the whole workspace, so that paused time drives every wait.

`libp2p_timer::Delay` and `libp2p_timer::bounded_delay` replace direct `futures-timer` and
`futures_bounded::Delay` construction across the tree. On native they bind their backend *eagerly,
at arm time* (construction or `reset`) via `tokio::runtime::Handle::try_current`: tokio's clock when
a runtime is present (pausable under `tokio::time::pause`, which is what makes the fork's
deterministic time-controlled tests possible) and `futures-timer` off-runtime. On wasm both are
plain `futures-timer`, because there is no tokio time driver in the browser. See the crate-level and
`mod native` docs in `src/lib.rs` for the precise panic-safety invariant.

## The timer sweep and its completeness oracle

`scripts/retimer.sh` mechanically routes every direct timer construction through this crate and,
via `--check`, guards against regressions in CI. Its completeness oracle fails if:

- a pre-sweep spelling (`futures_timer::`, `futures-timer` deps, `futures_bounded::Delay::…`)
  survives outside `misc/timer`, or
- a raw native `tokio::time::{sleep, interval, interval_at, timeout, Instant}` timer is armed in a
  shipped library `src/**` outside the allowlist below.

Only shipped library crates are scanned. `examples/**` and `interop-tests/**` (native-only sample
and harness binaries) and in-crate `#[cfg(test)]` modules are out of scope.

### Allowlisted native-only exceptions

These paths may use a native tokio timer directly; each wraps tokio's clock on purpose and is either
pausable or off the wasm reachability graph:

- **`misc/timer/**`** — the abstraction itself.
- **`transports/quic/src/provider/**`** — the QUIC runtime-provider seam, where the runtime's own
  timer primitive is the abstraction boundary.
- **`protocols/mdns/src/behaviour/timer.rs`** — mDNS arms a *periodic* timer
  (`Timer<Interval>` → `tokio::time::interval_at`) as a `futures::Stream`. `libp2p-timer` only
  offers a oneshot `Delay` future, so there is nothing to sweep this onto without reworking mDNS's
  generic `Provider` (timer/socket) abstraction. The exception is safe because the interval is still
  pausable under `tokio::time::pause` / `#[tokio::test(start_paused = true)]`, and `libp2p-mdns` has
  no wasm target (it needs raw UDP sockets), so the "tokio timer panics on wasm" hazard is
  unreachable. This is an *accepted* native-only exception, not a gap in the sweep.
