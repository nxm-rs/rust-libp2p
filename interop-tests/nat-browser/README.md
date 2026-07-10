# Double-NAT browser `/webrtc` interop topology

A docker compose topology for exercising the private-to-private `/webrtc` transport
under realistic network conditions: two peers, each behind its own MASQUERADE NAT,
with a shared "internet" that carries a coturn STUN/TURN server, a standalone
Circuit Relay v2 node (websockets) and redis for rendezvous.

```
                     pub 172.40.0.0/24 ("the internet")
     +----------------+--------------+--------------+
     |                |              |              |
  coturn .10       relay .11      redis .12         |
  STUN+TURN        circuit v2     rendezvous        |
     |                                              |
nat_a .2 (MASQUERADE)                   nat_b .3 (MASQUERADE)
     |                                              |
lan_a 172.41.0.0/24                     lan_b 172.42.0.0/24
     |                                              |
peer_a .10 (default route via .2)       peer_b .10 (default route via .2)
```

Peers are attached ONLY to their lan; their sole route to coturn, the relay, redis
and each other is through their NAT router. ICE therefore has to work with coturn
server-reflexive candidates (a real hole-punch through both NATs), with coturn TURN
as the automatic fallback.

The networks are deliberately not `internal: true`: docker drops any packet on an
internal bridge whose source or destination lies outside the bridge subnet, which
would kill the routed lan -> NAT -> pub path. Hermeticity comes from routing
instead: the NAT routers delete their default route, so neither they nor the peers
behind them can reach the docker host gateway or the real internet, and docker's
inter-bridge isolation blocks any direct lan_a <-> lan_b path.

## Fixed addresses and credentials

| what              | value                                                                 |
| ----------------- | --------------------------------------------------------------------- |
| STUN url          | `stun:172.40.0.10:3478`                                                |
| TURN url          | `turn:172.40.0.10:3478?transport=udp` (user `webrtc`, pass `webrtc`, realm `natwebrtc.test`, lt-cred-mech, no TLS) |
| relay multiaddr   | `/ip4/172.40.0.11/tcp/4455/ws/p2p/12D3KooWBXu3uGPMkjjxViK6autSnFH5QaKJgTwW8CaSxYSD6yYL` |
| redis             | `172.40.0.12:6379`                                                     |
| nat_a pub / lan   | `172.40.0.2` / `172.41.0.2`                                            |
| nat_b pub / lan   | `172.40.0.3` / `172.42.0.2`                                            |
| peer_a / peer_b   | `172.41.0.10` / `172.42.0.10`                                          |

The relay multiaddr is static because `src/bin/relay.rs` derives its keypair from
`RELAY_SEED` (default `42`); change the seed and the peer id changes with it.

Use IPs, not service names: docker DNS only resolves names of containers that share
a network, and the peers do not share a network with the pub services.

## How a peer is injected into a lan

Each peer slot is two services:

- `netns_X`: a tiny alpine container that owns the network namespace. It is the
  container attached to `lan_X` with the static IP, runs with `NET_ADMIN` and
  executes `ip route replace default via <nat lan ip>` before reporting healthy.
- `peer_X`: the actual peer image, started with `network_mode: service:netns_X`
  and `depends_on: netns_X: condition: service_healthy`. The peer image therefore
  needs no capabilities and no iproute2; its default route is already the NAT when
  its entrypoint runs, and it cannot be attached to `pub` by construction.

Swap peer images per slot via environment interpolation:

```sh
PEER_A_IMAGE=webrtc-interop-rust PEER_A_CMD=listener \
PEER_B_IMAGE=webrtc-interop-js   PEER_B_CMD=dialer \
docker compose -p natwebrtc-mypair -f docker-compose.nat.yml up
```

Every slot already receives the STUN url and infrastructure addresses in both
spellings the peers understand:

- `ice_server` (rust harness: `native_ping`, `wasm_ping`) and `ICE_SERVER`
  (js peer, `webrtc_p2p_interop` example): `stun:172.40.0.10:3478` by default;
  override with `ICE_SERVER=turn:...` to force the TURN fallback.
- `relay_addr` / `RELAY_ADDR`: the standalone relay multiaddr above. The wasm and
  native harnesses skip their in-process relay when this is set, which is essential
  here: an in-process relay would land on one peer's lan, unreachable by the other.
- `redis_addr`, `transport=webrtc`, `is_dialer` / `MODE` per slot.

For the browser (wasm) peer, run the `wasm_ping` harness inside the slot image with
stock Chrome + chromedriver (e.g. based on `selenium/standalone-chrome`); the
harness threads `ice_server` and `relay_addr` from the container env into the page.

## The four peer images

`build-images.sh` builds one image per peer type (plus the relay and NAT router
images). All four share the same rendezvous (redis `listenerAddr` list), the same
external relay and the same STUN knob, so any of the 16 listener/dialer pairings
works. Every image accepts `listener` or `dialer` as its container command.

| type          | image                        | what runs inside                                                        |
| ------------- | ---------------------------- | ----------------------------------------------------------------------- |
| `rust-native` | `natwebrtc-peer-rust-native` | the rust interop harness binary (`native_ping`), `libp2p-webrtc` tokio  |
| `rust-wasm`   | `natwebrtc-peer-rust-wasm`   | `wasm_ping` + stock Chrome/chromedriver (selenium base), `libp2p-webrtc-websys` wasm bundle |
| `js-node`     | `natwebrtc-peer-js-node`     | `js-webrtc/` peer on node 22, `@libp2p/webrtc` + node-datachannel       |
| `js-browser`  | `natwebrtc-peer-js-browser`  | `peers/js-browser/` esbuild bundle of `@libp2p/webrtc` in stock Chrome, driven by playwright-core |

Host prerequisites for `build-images.sh`: cargo with the wasm32 std, `wasm-pack`,
and a static libc (`native_ping`/`wasm_ping` are linked with crt-static so any
base image works). On NixOS run the steps in separate shells (a visible static
libc breaks proc-macro dylib linking during the wasm build):

```sh
./build-images.sh relay
nix-shell -p wasm-pack --run './build-images.sh wasm'
nix-shell -p glibc.static --run './build-images.sh bins'
./build-images.sh docker
```

## Running a pair

```sh
./run-pair.sh <peerA> <peerB>   # peerA = listener in lan_a, peerB = dialer in lan_b
./run-pair.sh rust-wasm js-node
```

The script brings the topology up under a unique compose project
(`natwebrtc-<peerA>-<peerB>`), waits for the dialer to finish, asserts a
successful libp2p ping over a connection whose remote address contains
`/webrtc`, prints the winning ICE candidate pair per peer (srflx vs relay, see
below), captures all container logs under `logs/pair-*/` and tears everything
down (`down -v --remove-orphans`). `ICE_SERVER='turn:172.40.0.10:3478?transport=udp'`
forces the TURN fallback path.

## Smoking the peer images

```sh
./smoke-peers.sh                # all four types
./smoke-peers.sh js-browser     # a subset
```

Per image (injected as the lan_a listener, no pair): asserts that the container
boots and builds a libp2p node, that its relay reservation succeeds through the
NAT (the advertised `/p2p-circuit/webrtc` multiaddr appears in redis) and that a
STUN binding from inside the peer's network namespace yields a server-reflexive
candidate equal to nat_a's pub address.

## Self-check

```sh
./selfcheck.sh
```

Builds the relay binary on the host (`cargo build -p interop-tests --bin relay`,
warm target dir via `WEBRTC_INTEROP_TARGET_DIR` or `CARGO_TARGET_DIR`), patches the
ELF interpreter for non-FHS hosts, brings the topology up under the
`natwebrtc-selfcheck` compose project and asserts:

1. the standalone relay printed its advertised multiaddr,
2. each peer reaches coturn/redis/relay through its NAT,
3. `turnutils_stunclient` run inside each peer namespace obtains a server-reflexive
   candidate from coturn whose address is the peer's NAT pub address (proving both
   STUN and MASQUERADE),
4. the lans are NOT directly connected (pings to the other peer's private address
   fail in both directions).

Logs (checks + full per-container compose logs) land under `logs/`. Teardown is
`down -v --remove-orphans`, always.

## Reporting the winning ICE pair

For every successful connection, report whether the nominated pair was srflx (true
hole-punch) or relay (TURN fallback). `scripts/ice-report.sh <logfile>` classifies
captured peer logs; make sure the peers log their selected pair:

- native rust peers: `RUST_LOG=webrtc_ice=debug` (already the slot default).
- js peers: log `pc.getStats()` candidate-pair entries with `nominated=true`.
- browser peers: capture the console / chrome webrtc-internals output.
