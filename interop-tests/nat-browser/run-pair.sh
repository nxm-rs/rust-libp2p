#!/usr/bin/env bash
# Runs one /webrtc interop pair across the double-NAT + coturn topology:
#
#   run-pair.sh <peerA> <peerB>
#
# peerA is injected into lan_a as the LISTENER, peerB into lan_b as the DIALER.
# Peer types: rust-native | rust-wasm | js-browser
#
# Both peers can only reach the pub network (coturn STUN/TURN, the standalone
# circuit relay, redis) through their MASQUERADE NAT, so the direct connection
# must be hole-punched via coturn server-reflexive candidates (or fall back to
# TURN). The script asserts a successful libp2p ping over a connection whose
# remote address contains /webrtc, captures all container logs under logs/, and
# reports whether the winning ICE candidate pair was srflx (a true hole-punch)
# or relay (TURN fallback).
#
# Env knobs:
#   TEST_TIMEOUT_SECONDS  per-peer timeout (default 180)
#   ICE_SERVER            override the STUN url, e.g. force TURN:
#                         ICE_SERVER='turn:172.40.0.10:3478?transport=udp'
#                         (credentials webrtc/webrtc, see the compose file)
#   FORCE_BUILD=1         re-run build-images.sh even if all images exist
#   KEEP=1                skip teardown (debugging)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "usage: $0 <peerA=listener> <peerB=dialer>" >&2
    echo "  peer types: rust-native | rust-wasm | js-browser" >&2
    exit 2
}

image_for() {
    case "$1" in
        rust-native) echo natwebrtc-peer-rust-native ;;
        rust-wasm) echo natwebrtc-peer-rust-wasm ;;
        js-browser) echo natwebrtc-peer-js-browser ;;
        *) echo "unknown peer type: $1" >&2; usage ;;
    esac
}

[ $# -eq 2 ] || usage
PEER_A_TYPE=$1
PEER_B_TYPE=$2
PEER_A_IMAGE="$(image_for "$PEER_A_TYPE")"
PEER_B_IMAGE="$(image_for "$PEER_B_TYPE")"

TIMEOUT="${TEST_TIMEOUT_SECONDS:-180}"
PROJECT="${COMPOSE_PROJECT:-natwebrtc-${PEER_A_TYPE}-${PEER_B_TYPE}}"
LOG_DIR="$SCRIPT_DIR/logs/pair-${PEER_A_TYPE}-${PEER_B_TYPE}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOG_DIR"

log() { echo "==> $*"; }

# ------------------------------------------------------------------ build if needed
missing=0
for img in "$PEER_A_IMAGE" "$PEER_B_IMAGE" natwebrtc-relay natwebrtc-natrouter; do
    docker image inspect "$img" >/dev/null 2>&1 || missing=1
done
if [ "$missing" -eq 1 ] || [ "${FORCE_BUILD:-0}" = 1 ]; then
    log "building images (missing=$missing, FORCE_BUILD=${FORCE_BUILD:-0})"
    "$SCRIPT_DIR/build-images.sh"
fi

compose() {
    PEER_A_IMAGE="$PEER_A_IMAGE" PEER_A_CMD=listener \
    PEER_A_MODE=listener PEER_A_IS_DIALER=false \
    PEER_B_IMAGE="$PEER_B_IMAGE" PEER_B_CMD=dialer \
    PEER_B_MODE=dialer PEER_B_IS_DIALER=true \
    TEST_TIMEOUT_SECONDS="$TIMEOUT" \
    docker compose -p "$PROJECT" -f "$SCRIPT_DIR/docker-compose.nat.yml" "$@"
}

teardown() {
    for svc in coturn relay redis nat_a nat_b netns_a netns_b peer_a peer_b; do
        compose logs --no-color --timestamps "$svc" >"$LOG_DIR/$svc.log" 2>&1 || true
    done
    if [ "${KEEP:-0}" = 1 ]; then
        log "KEEP=1: leaving project $PROJECT running; logs in $LOG_DIR"
        return
    fi
    log "tearing down (project $PROJECT)"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    log "logs: $LOG_DIR"
}
trap teardown EXIT

# ------------------------------------------------------------------------- run
log "pair: $PEER_A_TYPE (listener, lan_a) <-- /webrtc --> $PEER_B_TYPE (dialer, lan_b)"
log "bringing the topology up (project $PROJECT)"
compose up -d
compose ps -a >"$LOG_DIR/ps.txt" 2>&1

dialer_cid="$(compose ps -aq peer_b)"
[ -n "$dialer_cid" ] || { log "FAIL: dialer container not found"; exit 1; }

log "waiting up to $((TIMEOUT + 60))s for the dialer to finish"
rc=124
if wait_out="$(timeout "$((TIMEOUT + 60))" docker wait "$dialer_cid" 2>/dev/null)"; then
    rc="$wait_out"
fi

# Give a browser listener a moment to report its selected ICE pair (the shim polls
# getStats once a second and posts the result asynchronously).
sleep 5

# Capture logs before teardown so the assertions below can read them.
dialer_log="$LOG_DIR/peer_b.log"
listener_log="$LOG_DIR/peer_a.log"
compose logs --no-color peer_b >"$dialer_log" 2>&1 || true
compose logs --no-color peer_a >"$listener_log" 2>&1 || true

# --------------------------------------------------------------------- asserts
fail=0

if [ "$rc" = 124 ]; then
    log "FAIL: dialer did not finish within $((TIMEOUT + 60))s"
    fail=1
elif [ "$rc" != 0 ]; then
    log "FAIL: dialer exited with code $rc"
    fail=1
else
    log "PASS: dialer exited 0"
fi

# Every dialer only reports success for a ping on a connection whose remote
# address contains /webrtc: the rust harness (native_ping/wasm_ping) gates on
# Protocol::WebRTC before counting the ping, the js peers assert the dialled
# connection's remoteAddr includes /webrtc.
if grep -qaE 'pingRTTMilllis|JS_INTEROP_OK|JS_BROWSER_INTEROP_OK' "$dialer_log"; then
    log "PASS: dialer reported a successful ping over /webrtc:"
    grep -aE 'pingRTTMilllis|JS_INTEROP_OK|JS_BROWSER_INTEROP_OK' "$dialer_log" \
        | tail -n 1 | sed 's/^/    /'
else
    log "FAIL: no success report in the dialer log"
    fail=1
fi

# ------------------------------------------------------- winning ICE pair report
log "selected ICE candidate pair (srflx = hole-punch, relay = TURN fallback):"
"$SCRIPT_DIR/scripts/ice-report.sh" "$listener_log" "$dialer_log" || \
    log "WARN: could not classify the selected pair for every peer (see above)"

if [ "$fail" -eq 0 ]; then
    log "PAIR GREEN: $PEER_A_TYPE <-> $PEER_B_TYPE"
    exit 0
fi
log "PAIR RED: $PEER_A_TYPE <-> $PEER_B_TYPE (logs: $LOG_DIR)"
exit 1
