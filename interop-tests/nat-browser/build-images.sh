#!/usr/bin/env bash
# Builds everything the double-NAT /webrtc interop rig needs:
#
#   1. the wasm-pack bundle of the interop harness (embedded into wasm_ping),
#   2. static `native_ping` + `wasm_ping` binaries (host cargo, crt-static, so any
#      container base image works regardless of glibc),
#   3. the standalone relay binary (debug, ELF-interpreter-normalized like
#      selfcheck.sh does),
#   4. the docker images: relay + NAT router (via compose) and the three peer
#      images (rust-native, rust-wasm, js-browser).
#
# Usage: build-images.sh [step ...]     steps: wasm bins relay docker (default: all)
#
# Host prerequisites: cargo with the wasm32-unknown-unknown std (for `wasm`),
# wasm-pack, and a static libc for crt-static linking (for `bins`). On NixOS a
# visible static libc breaks any -shared link (proc-macro dylibs pick up the
# static libc.a and fail with TPOFF32 relocation errors), so run `bins` in its
# own shell and everything else in a plain one:
#
#   ./build-images.sh relay                                  # plain shell
#   nix-shell -p wasm-pack --run './build-images.sh wasm'    # rustup wasm32 std in PATH
#   nix-shell -p glibc.static --run './build-images.sh bins'
#   ./build-images.sh docker
#
# On a cold cargo cache, `bins` may still fail linking a host proc-macro inside
# the glibc.static shell; warm the host artifacts first by running the same
# cargo command in a plain shell (it fails later, at the aws-lc-sys link against
# the then-missing static libc, having built the proc-macros) and re-run.
#
# The cargo target dir is shared and warm via WEBRTC_INTEROP_TARGET_DIR or
# CARGO_TARGET_DIR.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="${WEBRTC_INTEROP_TARGET_DIR:-${CARGO_TARGET_DIR:-$REPO_ROOT/target}}"
STATIC_TARGET=x86_64-unknown-linux-gnu

STEPS=("$@")
[ ${#STEPS[@]} -gt 0 ] || STEPS=(wasm bins relay docker)

run_step() {
    local step=$1
    for s in "${STEPS[@]}"; do
        [ "$s" = "$step" ] && return 0
    done
    return 1
}

mkdir -p "$SCRIPT_DIR/bin"

if run_step wasm; then
    echo "==> wasm-pack bundle (target dir: $TARGET_DIR)"
    CARGO_TARGET_DIR="$TARGET_DIR" wasm-pack build --target web "$REPO_ROOT/interop-tests"
fi

if run_step bins; then
    echo "==> static native_ping + wasm_ping ($STATIC_TARGET, crt-static)"
    RUSTFLAGS='-C target-feature=+crt-static' cargo build \
        --config "build.target-dir=\"$TARGET_DIR\"" \
        --manifest-path "$REPO_ROOT/Cargo.toml" \
        --release --package interop-tests --target "$STATIC_TARGET" \
        --bin wasm_ping --bin native_ping

    cp -f "$TARGET_DIR/$STATIC_TARGET/release/native_ping" "$SCRIPT_DIR/bin/native_ping"
    cp -f "$TARGET_DIR/$STATIC_TARGET/release/wasm_ping" "$SCRIPT_DIR/bin/wasm_ping"
    if command -v strip >/dev/null 2>&1; then
        strip "$SCRIPT_DIR/bin/native_ping" "$SCRIPT_DIR/bin/wasm_ping"
    fi
fi

if run_step relay; then
    echo "==> standalone relay binary"
    cargo build \
        --config "build.target-dir=\"$TARGET_DIR\"" \
        --manifest-path "$REPO_ROOT/Cargo.toml" \
        -p interop-tests --bin relay
    cp -f "$TARGET_DIR/debug/relay" "$SCRIPT_DIR/bin/relay"
    if command -v strip >/dev/null 2>&1; then
        strip "$SCRIPT_DIR/bin/relay"
    fi

    # NixOS toolchains hardcode a /nix/store ELF interpreter that does not exist
    # inside the debian runtime image; point the (dynamic) relay binary at the
    # standard loader. The peer binaries are static-pie and need no fixup.
    if command -v patchelf >/dev/null 2>&1; then
        interp="$(patchelf --print-interpreter "$SCRIPT_DIR/bin/relay")"
        case "$interp" in
            /lib*/ld-linux*) ;;
            *)
                echo "==> patching relay ELF interpreter ($interp -> /lib64/ld-linux-x86-64.so.2)"
                patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 --remove-rpath \
                    "$SCRIPT_DIR/bin/relay"
                ;;
        esac
    fi
fi

if run_step docker; then
    for bin in relay native_ping wasm_ping; do
        [ -f "$SCRIPT_DIR/bin/$bin" ] \
            || { echo "ERROR: bin/$bin missing, run the host build steps first" >&2; exit 1; }
    done

    echo "==> docker: relay + NAT router images"
    docker compose -f "$SCRIPT_DIR/docker-compose.nat.yml" build

    echo "==> docker: peer images"
    # build_peer <image-tag> <dockerfile> <context>. A peer whose context or
    # Dockerfile is absent is skipped, never fatal: this rig must not abort just
    # because an optional peer harness was removed (js-webrtc was deleted).
    build_peer() {
        local tag=$1 dockerfile=$2 context=$3
        if [ ! -f "$dockerfile" ] || [ ! -d "$context" ]; then
            echo "==> skip $tag (missing $dockerfile or $context)"
            return 0
        fi
        docker build -f "$dockerfile" -t "$tag" "$context"
    }

    # Core hole-punch peers first (srflx via coturn): rust-native, rust-wasm and
    # js-browser. Ordering them ahead of any optional peer guarantees a missing
    # optional harness can never abort the core rig under `set -e`.
    build_peer natwebrtc-peer-rust-native "$SCRIPT_DIR/peers/rust-native/Dockerfile" "$SCRIPT_DIR"
    build_peer natwebrtc-peer-rust-wasm   "$SCRIPT_DIR/peers/rust-wasm/Dockerfile"   "$SCRIPT_DIR"
    build_peer natwebrtc-peer-js-browser  "$SCRIPT_DIR/peers/js-browser/Dockerfile"  "$SCRIPT_DIR/peers/js-browser"

    echo "==> done: natwebrtc-peer-{rust-native,rust-wasm,js-browser}"
fi
