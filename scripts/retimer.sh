#!/usr/bin/env bash
#
# Regenerate the mechanical timer sweep: route every direct timer construction in the tree through
# `libp2p-timer`. The output of this script is the final commit in the timer patch series; never
# hand-edit that commit, change this script and regenerate instead.
#
# Rules (all skip `misc/timer`, which is the abstraction itself, and the workspace root manifest,
# which keeps the `futures-timer` and `futures-bounded` dependency definitions):
#   1. `futures_timer::Delay`                 -> `libp2p_timer::Delay`
#   2. `futures_bounded::Delay::{tokio,futures_timer}(` -> `libp2p_timer::bounded_delay(`
#   3. consumer manifests: swap the `futures-timer` dependency for `libp2p-timer`, delete the two
#      wasm-gated `wasm-bindgen` entries (centralised in `misc/timer`), and insert `libp2p-timer`
#      where a crate now calls `libp2p_timer::` but did not depend on `futures-timer`.
#   4. workspace `futures-bounded`: drop the `tokio` feature (re-added only in `misc/timer`), keep
#      `futures-timer`.
#   5. completeness oracle: fail if any pre-sweep spelling survives outside `misc/timer`.
#   6. format with nightly rustfmt (the repo's unstable import options require it).

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Completeness oracle: any surviving pre-sweep spelling outside `misc/timer` is a rule the sweep
# could not express, so fail loudly rather than silently regress pausability. Runs at the end of a
# sweep and, via `--check`, as the CI drift guard.
run_oracle() {
    local fail=0
    if rg -q --glob '*.rs' -g '!misc/timer/**' 'futures_timer::'; then
        echo "retimer oracle: 'futures_timer::' survives in a .rs file outside misc/timer" >&2
        fail=1
    fi
    if rg -q --glob '*Cargo.toml' -g '!misc/timer/**' -g '!/Cargo.toml' 'futures-timer'; then
        echo "retimer oracle: 'futures-timer' survives in a non-root Cargo.toml outside misc/timer" >&2
        fail=1
    fi
    if rg -q --glob '*.rs' -g '!misc/timer/**' 'futures_bounded::Delay::'; then
        echo "retimer oracle: a 'futures_bounded::Delay::' constructor survives outside misc/timer" >&2
        fail=1
    fi
    if rg -q --glob '*.rs' -g '!misc/timer/**' '\bDelay::(tokio|futures_timer)\('; then
        echo "retimer oracle: a bare 'Delay::{tokio,futures_timer}(' call survives outside misc/timer" >&2
        fail=1
    fi
    return "$fail"
}

# `--check` runs only the oracle (no mutations), which is what the CI guard invokes on every PR.
if [ "${1:-}" = "--check" ]; then
    run_oracle
    exit
fi

# Both `Delay::tokio` and `Delay::futures_timer` are accepted so the sweep survives an upstream
# rebase that flips the `futures_bounded` constructor spelling.
while IFS= read -r file; do
    sed -i \
        -e 's/futures_timer::Delay/libp2p_timer::Delay/g' \
        -e 's/futures_bounded::Delay::tokio(/libp2p_timer::bounded_delay(/g' \
        -e 's/futures_bounded::Delay::futures_timer(/libp2p_timer::bounded_delay(/g' \
        "$file"
done < <(rg -l --glob '*.rs' -g '!misc/timer/**' \
    -e 'futures_timer::Delay' -e 'futures_bounded::Delay::' || true)

# The wasm `wasm-bindgen` feature now flows transitively from `misc/timer`; drop the local entries.
for manifest in libp2p/Cargo.toml protocols/gossipsub/Cargo.toml; do
    sed -i '/^futures-timer = { workspace = true, features = \["wasm-bindgen"\] }$/d' "$manifest"
done

# Swap every plain `futures-timer` workspace dependency for `libp2p-timer`.
while IFS= read -r manifest; do
    sed -i 's/^futures-timer = { workspace = true }$/libp2p-timer = { workspace = true }/' "$manifest"
done < <(rg -l --glob '*Cargo.toml' -g '!misc/timer/**' -g '!/Cargo.toml' \
    '^futures-timer = \{ workspace = true \}$' || true)

# Insert `libp2p-timer` into any crate that now calls `libp2p_timer::` but has no dependency on it
# (the crates that only used `futures_bounded::Delay::tokio`, e.g. request-response).
while IFS= read -r crate; do
    manifest="$crate/Cargo.toml"
    [ -f "$manifest" ] || continue
    if ! rg -q '^libp2p-timer = ' "$manifest"; then
        sed -i '0,/^\[dependencies\]$/s//[dependencies]\nlibp2p-timer = { workspace = true }/' "$manifest"
    fi
done < <(rg -l --glob '*.rs' -g '!misc/timer/**' 'libp2p_timer::' \
    | sed -e 's#/src/.*##' -e 's#/tests/.*##' -e 's#/benches/.*##' -e 's#/examples/[^/]*\.rs$##' \
    | sort -u || true)

# The workspace default no longer needs tokio; `misc/timer` re-adds it in its native target table.
sed -i \
    's/^futures-bounded = { version = "0.3", features = \["tokio"\] }$/futures-bounded = { version = "0.3", features = ["futures-timer"] }/' \
    Cargo.toml

run_oracle

# Reconcile Cargo.lock with the rewritten manifests: the sweep adds `libp2p-timer` and drops
# `futures-timer` per crate, with no version bumps, so this only edits dependency lists. CI's
# `ensure-lockfile-uptodate` job runs `cargo metadata --locked` and fails on a stale lock.
cargo metadata --format-version=1 > /dev/null

# CI formats with nightly and unstable import options; stable fmt misses the repo style.
cargo +nightly fmt --all
