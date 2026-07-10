// Wraps window.RTCPeerConnection before the libp2p bundle loads and, once a
// connection reaches the `connected` state, logs the nominated candidate pair
// from getStats(). The candidate types (host/srflx/relay) tell whether the
// double-NAT was hole-punched via STUN or fell back to a TURN relay; the
// playwright driver forwards console lines to its stdout, where
// nat-browser/scripts/ice-report.sh classifies them.
(() => {
    const Native = window.RTCPeerConnection;
    if (!Native) {
        return;
    }

    async function report(pc) {
        const stats = await pc.getStats();
        const byId = new Map();
        stats.forEach((s) => byId.set(s.id, s));
        let pair = null;
        stats.forEach((s) => {
            if (s.type === "transport" && s.selectedCandidatePairId) {
                pair = byId.get(s.selectedCandidatePairId) ?? pair;
            }
        });
        if (!pair) {
            stats.forEach((s) => {
                if (!pair && s.type === "candidate-pair"
                    && s.state === "succeeded" && (s.nominated || s.selected)) {
                    pair = s;
                }
            });
        }
        if (!pair) {
            return false;
        }
        const local = byId.get(pair.localCandidateId) ?? {};
        const remote = byId.get(pair.remoteCandidateId) ?? {};
        const fmt = (c) =>
            `${c.candidateType ?? "?"} ${c.ip ?? c.address ?? "?"}:${c.port ?? "?"}`;
        const line = `ICE_SELECTED_PAIR local=${fmt(local)} remote=${fmt(remote)}`
            + " (selected candidate pair)";
        console.log(line);
        window.__icePair = line;
        return true;
    }

    window.RTCPeerConnection = class extends Native {
        constructor(...args) {
            super(...args);
            const poll = setInterval(async () => {
                const state = this.connectionState;
                if (state === "closed" || state === "failed") {
                    clearInterval(poll);
                    return;
                }
                if ((state === "connected" || this.iceConnectionState === "connected")
                    && await report(this).catch(() => false)) {
                    clearInterval(poll);
                }
            }, 1000);
        }
    };
})();
