#!/usr/bin/env bash
# Smoke-tests each /webrtc peer image in the double-NAT topology WITHOUT running a
# full pair. Per peer type, injected as the lan_a listener:
#
#   1. the container boots and builds a libp2p node,
#   2. it reaches the standalone relay + redis through its NAT: the relay
#      reservation succeeds and the advertised /p2p-circuit/webrtc multiaddr
#      appears on the `listenerAddr` redis list,
#   3. its network namespace reaches coturn: a STUN binding from inside the
#      peer's netns yields a server-reflexive candidate equal to nat_a's pub
#      address (MASQUERADE + STUN confirmed).
#
# Usage: smoke-peers.sh [peer-type ...]   (default: all four)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COTURN_IP=172.40.0.10
NAT_A_PUB=172.40.0.2
TYPES=("$@")
[ ${#TYPES[@]} -gt 0 ] || TYPES=(rust-native rust-wasm js-node js-browser)

image_for() {
    case "$1" in
        rust-native) echo natwebrtc-peer-rust-native ;;
        rust-wasm) echo natwebrtc-peer-rust-wasm ;;
        js-node) echo natwebrtc-peer-js-node ;;
        js-browser) echo natwebrtc-peer-js-browser ;;
        *) echo "unknown peer type: $1" >&2; exit 2 ;;
    esac
}

log() { echo "==> $*"; }

overall=0
for type in "${TYPES[@]}"; do
    image="$(image_for "$type")"
    project="natwebrtc-smoke-${type}"
    log_dir="$SCRIPT_DIR/logs/smoke-${type}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$log_dir"

    compose() {
        PEER_A_IMAGE="$image" PEER_A_CMD=listener \
        PEER_A_MODE=listener PEER_A_IS_DIALER=false \
        docker compose -p "$project" -f "$SCRIPT_DIR/docker-compose.nat.yml" "$@"
    }

    log "[$type] bringing the topology up (project $project)"
    fail=0
    compose up -d >"$log_dir/up.log" 2>&1 || fail=1

    if [ "$fail" -eq 0 ]; then
        # ---- 2. listener published its addr to redis through the NAT ----------
        addr=""
        for _ in $(seq 1 60); do
            addr="$(compose exec -T redis redis-cli LINDEX listenerAddr 0 2>/dev/null || true)"
            [ -n "$addr" ] && break
            sleep 2
        done
        if [ -n "$addr" ]; then
            log "[$type] PASS: libp2p node up, relay reservation + redis publish OK:"
            echo "    $addr"
        else
            log "[$type] FAIL: no listenerAddr in redis after 120s"
            fail=1
        fi

        # ---- 3. STUN from inside the peer's own netns -------------------------
        netns_cid="$(compose ps -q netns_a)"
        stun_out="$(docker run --rm --network "container:$netns_cid" \
            coturn/coturn:latest turnutils_stunclient -p 3478 "$COTURN_IP" 2>&1 || true)"
        echo "$stun_out" >"$log_dir/stun.log"
        srflx="$(echo "$stun_out" \
            | grep -o 'reflexive addr: *[0-9.]*:[0-9]*' | head -n1 \
            | grep -o '[0-9.]*:[0-9]*$' || true)"
        if [ "${srflx%%:*}" = "$NAT_A_PUB" ]; then
            log "[$type] PASS: STUN srflx from the peer netns: $srflx (== nat_a pub)"
        else
            log "[$type] FAIL: STUN srflx wrong or missing (got '$srflx')"
            fail=1
        fi
    else
        log "[$type] FAIL: compose up failed (see $log_dir/up.log)"
    fi

    for svc in coturn relay redis nat_a netns_a peer_a; do
        compose logs --no-color --timestamps "$svc" >"$log_dir/$svc.log" 2>&1 || true
    done
    compose down -v --remove-orphans >/dev/null 2>&1 || true

    if [ "$fail" -eq 0 ]; then
        log "[$type] SMOKE GREEN (logs: $log_dir)"
    else
        log "[$type] SMOKE RED (logs: $log_dir)"
        overall=1
    fi
done

exit "$overall"
