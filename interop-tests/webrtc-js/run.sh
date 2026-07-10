#!/usr/bin/env bash
# One-shot rust <-> js private-to-private /webrtc interop round.
#
# 1. Builds the rust interop binary ON THE HOST (fast, warm shared target
#    dir; override with WEBRTC_INTEROP_TARGET_DIR or CARGO_TARGET_DIR).
# 2. Normalises the ELF interpreter (NixOS hosts emit /nix/store paths) and
#    strips debug info so the docker context stays small.
# 3. Builds both images, runs `docker compose -p webrtc-interop up` and
#    asserts the js dialer printed JS_INTEROP_OK, i.e. a real ping crossed a
#    direct /webrtc connection to the rust listener.
# 4. Captures all container logs to logs/run-<timestamp>.log and always
#    tears down with `down -v --remove-orphans`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT="${COMPOSE_PROJECT:-webrtc-interop}"
TARGET_DIR="${WEBRTC_INTEROP_TARGET_DIR:-${CARGO_TARGET_DIR:-$REPO_ROOT/target}}"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/run-$(date +%Y%m%d-%H%M%S).log"
BIN="$SCRIPT_DIR/bin/webrtc_p2p_interop"

mkdir -p "$LOG_DIR" "$SCRIPT_DIR/bin"

echo "==> building rust interop binary (target dir: $TARGET_DIR)"
cargo build \
    --config "build.target-dir=\"$TARGET_DIR\"" \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p interop-tests --example webrtc_p2p_interop

cp -f "$TARGET_DIR/debug/examples/webrtc_p2p_interop" "$BIN"

# Shrink the docker context: the debug example carries ~300 MB of debug info.
if command -v strip >/dev/null 2>&1; then
    strip "$BIN"
fi

# NixOS toolchains hardcode a /nix/store ELF interpreter that does not exist
# inside the debian runtime image; point it at the standard loader instead.
if command -v patchelf >/dev/null 2>&1; then
    interp="$(patchelf --print-interpreter "$BIN")"
    case "$interp" in
        /lib*/ld-linux*) ;;
        *)
            echo "==> patching ELF interpreter ($interp -> /lib64/ld-linux-x86-64.so.2)"
            patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 --remove-rpath "$BIN"
            ;;
    esac
fi

compose() {
    docker compose -p "$PROJECT" -f "$SCRIPT_DIR/docker-compose.yml" "$@"
}

cleanup() {
    echo "==> tearing down (project $PROJECT)"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> building images"
compose build

echo "==> running interop round (log: $LOG_FILE)"
set +e
compose up --exit-code-from js-dialer 2>&1 | tee "$LOG_FILE"
status=${PIPESTATUS[0]}
set -e

# Keep a clean per-container copy of everything as well.
{
    echo
    echo "===== docker compose logs (per container, timestamped) ====="
    compose logs --no-color --timestamps
} >>"$LOG_FILE" 2>&1 || true

if [ "$status" -eq 0 ] && grep -q 'JS_INTEROP_OK' "$LOG_FILE"; then
    echo "==> INTEROP GREEN: js dialer pinged the rust listener over a direct /webrtc connection"
    exit 0
fi

echo "==> INTEROP RED (compose exit code $status); decisive lines:"
grep -E 'INTEROP_OK|INTEROP_FAIL|LISTENING_ON|ERROR|Error|error' "$LOG_FILE" | tail -40 || true
echo "==> full log: $LOG_FILE"
exit 1
