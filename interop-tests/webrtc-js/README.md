# rust <-> js private-to-private `/webrtc` interop harness

Docker compose wiring for one interop round between the rust peer
(`interop-tests/examples/webrtc_p2p_interop.rs`, running the embedded Circuit
Relay v2 server plus the `/webrtc` LISTENER) and the js peer
(`interop-tests/js-webrtc`, running the DIALER on node 22 via
`node-datachannel`).

Topology: one internal bridge network, no published host ports, no STUN or
TURN - ICE completes on container host candidates. The listener writes its
dialable address (`.../ws/p2p/<relay>/p2p-circuit/webrtc/p2p/<listener>`) to
`COORD_FILE` on a shared volume; the dialer polls it, dials, and pings over
the resulting direct `/webrtc` connection.

## Run

```sh
./run.sh
```

`run.sh` builds the rust binary on the host (set `WEBRTC_INTEROP_TARGET_DIR`
or `CARGO_TARGET_DIR` to keep a warm shared target dir), normalises the ELF
interpreter for the debian runtime image, builds both images, runs
`docker compose -p webrtc-interop up`, asserts the dialer printed
`JS_INTEROP_OK`, writes all container logs to `logs/run-<timestamp>.log` and
tears everything down with `down -v --remove-orphans`.

Green means: a ping request/response actually crossed a connection whose
remote multiaddr contains `/webrtc`, between the two implementations.
