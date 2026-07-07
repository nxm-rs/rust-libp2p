#!/usr/bin/env bash
# Classifies the winning ICE candidate pair for each peer in a captured log file:
# srflx (a true hole-punch through both NATs) vs relay (coturn TURN fallback).
#
# Usage: ice-report.sh <logfile>...
#
# Where the evidence comes from:
# - native rust peers (webrtc-rs): run with RUST_LOG=webrtc_ice=debug; the nominated
#   pair is logged as e.g. "candidate pair ... succeeded" / "set selected pair"
#   including both candidates' types (host/srflx/relay).
# - js peers (node-datachannel / browser): log the selected pair via
#   pc.getStats() (candidate-pair with state=succeeded + nominated=true) or
#   DEBUG=libp2p:webrtc* traces.
# - browser wasm peers: chrome logs "Selected candidate pair changed" in the
#   webrtc_internals dump; the harness log captures console output.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <logfile>..." >&2; exit 2; }

status=0
for f in "$@"; do
    echo "== $f"
    pair_lines="$(grep -aiE 'selected (candidate )?pair|candidate pair.*(succeeded|nominat)|nominat.*pair' "$f" || true)"
    if [ -z "$pair_lines" ]; then
        echo "   no selected-pair evidence found (enable RUST_LOG=webrtc_ice=debug or getStats logging)"
        status=1
        continue
    fi
    echo "$pair_lines" | tail -n 5 | sed 's/^/   /'
    if echo "$pair_lines" | grep -qi 'relay'; then
        echo "   WINNER: relay (TURN fallback via coturn)"
    elif echo "$pair_lines" | grep -qiE 'srflx|server.?reflexive|prflx'; then
        echo "   WINNER: srflx (hole-punched through both NATs)"
    else
        echo "   WINNER: host (unexpected in the double-NAT topology!)"
        status=1
    fi
done
exit $status
