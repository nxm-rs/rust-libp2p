# js-libp2p private-to-private `/webrtc` interop peer

Counterpart to `interop-tests/examples/webrtc_p2p_interop.rs`. Runs on node 22
using `@libp2p/webrtc` (the private-to-private `webRTC()` transport), which
resolves `RTCPeerConnection` from `node-datachannel` under node - no browser
is involved.

## Modes

- `node src/index.js dialer` - polls `COORD_FILE` for
  `<relay-ws>/p2p/<relay-id>/p2p-circuit/webrtc/p2p/<listener-id>`, dials it,
  waits for the direct `/webrtc` connection, pings on it, prints
  `JS_INTEROP_OK rtt_ms=<rtt>` and exits 0 (or `JS_INTEROP_FAIL: <reason>`,
  exit 1).
- `node src/index.js listener` - dials the Circuit Relay v2 server given by
  `RELAY_ADDR` (`.../ws/p2p/<relay-id>` or `.../tcp/...`), reserves a slot,
  listens on `/webrtc` and writes the dialable address to `COORD_FILE`
  (printed as `LISTENING_ON=<addr>`). Unlike the rust listener this mode does
  not embed a relay server.

## Environment

| Variable            | Default            | Meaning                                     |
| ------------------- | ------------------ | ------------------------------------------- |
| `MODE`              | -                  | `dialer` or `listener` (or first CLI arg)   |
| `COORD_FILE`        | `/coord/dial_addr` | shared file handing over the dial address   |
| `TEST_TIMEOUT_SECS` | `180`              | overall timeout                             |
| `ICE_SERVER`        | unset              | optional STUN/TURN url                      |
| `RELAY_ADDR`        | unset              | relay multiaddr (listener mode only)        |
| `DEBUG`             | unset              | js-libp2p debug filter, e.g. `libp2p:*`     |

## Build / smoke

```sh
npm ci
npm run smoke        # constructs the full stack, prints JS_SMOKE_OK
docker build -t webrtc-interop-js .   # smoke test runs during the build
```
