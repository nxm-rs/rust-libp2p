#!/usr/bin/env bash
# Topology self-check for the double-NAT + coturn STUN compose file.
#
# Proves, without running a full interop pair:
#   1. STUN: a peer behind nat_a/nat_b obtains a server-reflexive candidate from
#      coturn, and the mapped address is the NAT's pub address (not the lan address),
#      i.e. MASQUERADE is actually translating.
#   2. Reachability: peers reach coturn, redis and the standalone relay ONLY via
#      their NAT (ICMP + TCP checks from inside the peer namespace).
#   3. Isolation: lan_a and lan_b are NOT directly connected; a ping to the other
#      peer's private address fails.
#
# Builds the standalone relay binary on the host (warm shared target dir; override
# with WEBRTC_INTEROP_TARGET_DIR or CARGO_TARGET_DIR), normalizes the ELF interpreter
# for non-FHS hosts (NixOS), brings the topology up under a unique compose project
# and always tears down with `down -v --remove-orphans`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT="${COMPOSE_PROJECT:-natwebrtc-selfcheck}"
TARGET_DIR="${WEBRTC_INTEROP_TARGET_DIR:-${CARGO_TARGET_DIR:-$REPO_ROOT/target}}"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/selfcheck-$(date +%Y%m%d-%H%M%S).log"
BIN="$SCRIPT_DIR/bin/relay"

COTURN_IP=172.40.0.10
RELAY_IP=172.40.0.11
REDIS_IP=172.40.0.12
NAT_A_PUB=172.40.0.2
NAT_B_PUB=172.40.0.3
PEER_A_LAN=172.41.0.10
PEER_B_LAN=172.42.0.10

mkdir -p "$LOG_DIR" "$SCRIPT_DIR/bin"

log() { echo "==> $*" | tee -a "$LOG_FILE"; }

echo "==> building the standalone relay binary (target dir: $TARGET_DIR)"
cargo build \
    --config "build.target-dir=\"$TARGET_DIR\"" \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p interop-tests --bin relay

cp -f "$TARGET_DIR/debug/relay" "$BIN"

# Shrink the docker context: the debug binary carries a lot of debug info.
if command -v strip >/dev/null 2>&1; then
    strip "$BIN"
fi

# NixOS toolchains hardcode a /nix/store ELF interpreter that does not exist inside
# the debian runtime image; point it at the standard loader instead.
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
    docker compose -p "$PROJECT" -f "$SCRIPT_DIR/docker-compose.nat.yml" "$@"
}

cleanup() {
    {
        echo
        echo "===== docker compose logs (per container, timestamped) ====="
        compose logs --no-color --timestamps
    } >>"$LOG_FILE" 2>&1 || true
    echo "==> tearing down (project $PROJECT)"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    echo "==> full log: $LOG_FILE"
}
trap cleanup EXIT

log "building images"
compose build >>"$LOG_FILE" 2>&1

log "bringing the topology up (project $PROJECT)"
compose up -d --wait --wait-timeout 120 >>"$LOG_FILE" 2>&1 || {
    log "compose up --wait failed; container states:"
    compose ps -a | tee -a "$LOG_FILE"
    exit 1
}
compose ps -a >>"$LOG_FILE" 2>&1

fail=0
srflx_a=""
srflx_b=""

check() {
    local desc=$1 expected=$2
    shift 2
    local rc=0
    "$@" >>"$LOG_FILE" 2>&1 || rc=$?
    if { [ "$expected" = ok ] && [ "$rc" -eq 0 ]; } \
        || { [ "$expected" = fail ] && [ "$rc" -ne 0 ]; }; then
        log "PASS: $desc"
    else
        log "FAIL: $desc (exit $rc, expected $expected)"
        fail=1
    fi
}

# --- 0. relay came up and advertises the expected multiaddr -----------------------
relay_line="$(compose logs relay 2>/dev/null | grep -o 'RELAY_LISTENING_ON=.*' | head -n1 || true)"
if [ -n "$relay_line" ]; then
    log "PASS: standalone relay is up: $relay_line"
else
    log "FAIL: relay did not print RELAY_LISTENING_ON"
    fail=1
fi

# --- 1. routing inside the peer namespaces ----------------------------------------
log "peer_a routes:" && compose exec -T netns_a ip route | tee -a "$LOG_FILE"
log "peer_b routes:" && compose exec -T netns_b ip route | tee -a "$LOG_FILE"

# --- 2. reachability of the pub services through the NAT --------------------------
check "peer_a -> coturn ($COTURN_IP) via nat_a" ok \
    compose exec -T netns_a ping -c 1 -W 2 "$COTURN_IP"
check "peer_a -> redis ($REDIS_IP) via nat_a" ok \
    compose exec -T netns_a ping -c 1 -W 2 "$REDIS_IP"
check "peer_a -> relay tcp $RELAY_IP:4455 via nat_a" ok \
    compose exec -T peer_a timeout 3 bash -c "exec 3<>/dev/tcp/$RELAY_IP/4455"
check "peer_b -> coturn ($COTURN_IP) via nat_b" ok \
    compose exec -T netns_b ping -c 1 -W 2 "$COTURN_IP"
check "peer_b -> relay tcp $RELAY_IP:4455 via nat_b" ok \
    compose exec -T peer_b timeout 3 bash -c "exec 3<>/dev/tcp/$RELAY_IP/4455"

# --- 3. STUN: server-reflexive candidates from behind each NAT --------------------
stun_probe() {
    # turnutils_stunclient prints "UDP reflexive addr: <ip>:<port>" on success.
    local slot=$1
    compose exec -T "$slot" turnutils_stunclient -p 3478 "$COTURN_IP" 2>&1
}

out_a="$(stun_probe peer_a || true)"
echo "$out_a" >>"$LOG_FILE"
srflx_a="$(echo "$out_a" | grep -o 'reflexive addr: *[0-9.]*:[0-9]*' | head -n1 | grep -o '[0-9.]*:[0-9]*$' || true)"
if [ "${srflx_a%%:*}" = "$NAT_A_PUB" ]; then
    log "PASS: peer_a srflx candidate from coturn: $srflx_a (== nat_a pub addr, MASQUERADE confirmed)"
else
    log "FAIL: peer_a srflx candidate wrong or missing (got '$srflx_a', want ip $NAT_A_PUB)"
    fail=1
fi

out_b="$(stun_probe peer_b || true)"
echo "$out_b" >>"$LOG_FILE"
srflx_b="$(echo "$out_b" | grep -o 'reflexive addr: *[0-9.]*:[0-9]*' | head -n1 | grep -o '[0-9.]*:[0-9]*$' || true)"
if [ "${srflx_b%%:*}" = "$NAT_B_PUB" ]; then
    log "PASS: peer_b srflx candidate from coturn: $srflx_b (== nat_b pub addr, MASQUERADE confirmed)"
else
    log "FAIL: peer_b srflx candidate wrong or missing (got '$srflx_b', want ip $NAT_B_PUB)"
    fail=1
fi

# --- 4. lan isolation: no direct path between the lans ----------------------------
check "peer_a -/-> peer_b private addr ($PEER_B_LAN) is blocked" fail \
    compose exec -T netns_a ping -c 1 -W 2 "$PEER_B_LAN"
check "peer_b -/-> peer_a private addr ($PEER_A_LAN) is blocked" fail \
    compose exec -T netns_b ping -c 1 -W 2 "$PEER_A_LAN"

# --- 5. the NAT pub addresses answer for hole-punching ----------------------------
# A packet from peer_a to nat_b's pub address must at least route (that is the
# path hole-punched ICE traffic takes). ICMP to the NAT itself suffices here.
check "peer_a -> nat_b pub addr ($NAT_B_PUB) routes" ok \
    compose exec -T netns_a ping -c 1 -W 2 "$NAT_B_PUB"

if [ "$fail" -eq 0 ]; then
    log "SELFCHECK GREEN: srflx_a=$srflx_a srflx_b=$srflx_b, lans isolated, pub reachable only via NAT"
    exit 0
fi
log "SELFCHECK RED: see $LOG_FILE"
exit 1
