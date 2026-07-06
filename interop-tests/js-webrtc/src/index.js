/**
 * Standalone private-to-private `/webrtc` interop peer (js-libp2p side).
 *
 * Counterpart to `interop-tests/examples/webrtc_p2p_interop.rs`. Two roles,
 * selected by the `MODE` env var or the first CLI argument:
 *
 * - `dialer`: polls `COORD_FILE` for a multiaddr of the shape
 *   `<relay-ws-addr>/p2p/<relay-id>/p2p-circuit/webrtc/p2p/<listener-id>`,
 *   dials it, waits for the direct `/webrtc` connection and a successful ping
 *   on it, then prints `JS_INTEROP_OK` and exits 0. On failure prints
 *   `JS_INTEROP_FAIL: <reason>` and exits 1.
 * - `listener`: dials the relay given by `RELAY_ADDR`, reserves a slot
 *   (listens on `/p2p-circuit`) plus `/webrtc`, then writes its dialable
 *   address to `COORD_FILE` and prints `LISTENING_ON=<addr>`. Unlike the rust
 *   listener it does not embed a relay server, so `RELAY_ADDR` must point at
 *   an external Circuit Relay v2 server reachable over `/ws` or `/tcp`.
 *
 * Environment variables (mirroring the rust binary):
 *
 * - `MODE`: `listener` or `dialer` (fallback when no CLI argument is given).
 * - `COORD_FILE`: path used to hand the dial address over
 *   (default `/coord/dial_addr`), typically a shared docker volume.
 * - `TEST_TIMEOUT_SECS`: overall timeout (default `180`).
 * - `ICE_SERVER`: optional STUN/TURN url for the webrtc transport. Not needed
 *   on a flat docker bridge network where host candidates suffice.
 * - `RELAY_ADDR`: listener mode only, the relay multiaddr including
 *   `/p2p/<relay-id>`.
 * - `DEBUG`: standard js-libp2p debug filter, e.g. `libp2p:*webrtc*`.
 */

// @libp2p/webrtc resolves RTCPeerConnection from node-datachannel/polyfill by
// itself under node (see its dist/src/webrtc/index.js), but expose the
// polyfill globally too so anything probing `globalThis.RTCPeerConnection`
// before/afterwards finds a working implementation.
import { RTCIceCandidate, RTCPeerConnection, RTCSessionDescription } from 'node-datachannel/polyfill'

globalThis.RTCPeerConnection ??= RTCPeerConnection
globalThis.RTCSessionDescription ??= RTCSessionDescription
globalThis.RTCIceCandidate ??= RTCIceCandidate

const { createLibp2p } = await import('libp2p')
const { webRTC } = await import('@libp2p/webrtc')
const { circuitRelayTransport } = await import('@libp2p/circuit-relay-v2')
const { webSockets } = await import('@libp2p/websockets')
const { noise } = await import('@chainsafe/libp2p-noise')
const { yamux } = await import('@chainsafe/libp2p-yamux')
const { identify } = await import('@libp2p/identify')
const { ping } = await import('@libp2p/ping')
const { multiaddr } = await import('@multiformats/multiaddr')

const fs = await import('node:fs/promises')
const path = await import('node:path')
const { setTimeout: sleep } = await import('node:timers/promises')

const COORD_FILE = process.env.COORD_FILE ?? '/coord/dial_addr'
const TEST_TIMEOUT_SECS = Number.parseInt(process.env.TEST_TIMEOUT_SECS ?? '180', 10)
const ICE_SERVER = process.env.ICE_SERVER
const RELAY_ADDR = process.env.RELAY_ADDR

/** Protocol names of a multiaddr (multiaddr v13 dropped protoNames()). */
function protoNames (ma) {
  return ma.getComponents().map((component) => component.name)
}

function log (...args) {
  console.error(`[js-webrtc-interop ${new Date().toISOString()}]`, ...args)
}

/** Builds the js peer: /webrtc + circuit relay + websockets, noise + yamux. */
async function createNode ({ listen = [] } = {}) {
  return createLibp2p({
    addresses: { listen },
    transports: [
      webSockets(),
      circuitRelayTransport(),
      webRTC({
        rtcConfiguration: ICE_SERVER === undefined ? {} : { iceServers: [{ urls: ICE_SERVER }] }
      })
    ],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    // Interop peers live on private container networks: never refuse an addr.
    connectionGater: { denyDialMultiaddr: () => false },
    services: {
      identify: identify(),
      ping: ping()
    }
  })
}

/** Polls COORD_FILE until it contains a parseable multiaddr ending in /p2p/<id>. */
async function waitForAddr (signal) {
  for (;;) {
    signal.throwIfAborted()
    try {
      const contents = (await fs.readFile(COORD_FILE, 'utf8')).trim()
      if (contents !== '') {
        try {
          const addr = multiaddr(contents)
          const components = addr.getComponents()
          if (components.at(-1)?.name !== 'p2p') {
            throw new Error(`dial address must end in /p2p/<listener-peer-id>: ${contents}`)
          }
          return addr
        } catch (err) {
          log(`COORD_FILE holds an unparseable multiaddr: ${err.message}`)
        }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        log(`COORD_FILE not readable yet: ${err.message}`)
      }
    }
    await sleep(250, undefined, { signal })
  }
}

/** Writes the address atomically (write + rename), matching the rust peer. */
async function publishAddr (addr) {
  await fs.mkdir(path.dirname(COORD_FILE), { recursive: true })
  const tmp = `${COORD_FILE}.tmp`
  await fs.writeFile(tmp, `${addr.toString()}\n`)
  await fs.rename(tmp, COORD_FILE)
}

async function runDialer (signal) {
  const addr = await waitForAddr(signal)
  const node = await createNode()
  log(`dialer peer id ${node.peerId.toString()}, dialing ${addr.toString()}`)

  // Dialing the full `/p2p-circuit/webrtc/p2p/<id>` address makes the webRTC
  // transport establish the relayed signalling hop itself and resolve with the
  // direct connection once ICE completes.
  const conn = await node.dial(addr, { signal })
  if (!protoNames(conn.remoteAddr).includes('webrtc')) {
    throw new Error(`dial resolved with a non-webrtc connection: ${conn.remoteAddr.toString()}`)
  }
  log(`direct /webrtc connection established: ${conn.remoteAddr.toString()}`)

  // A relayed connection to the listener may remain open after signalling.
  // Close it so the ping below can only run on the direct /webrtc connection.
  for (const other of node.getConnections(conn.remotePeer)) {
    if (other.id !== conn.id) {
      log(`closing non-webrtc connection ${other.remoteAddr.toString()}`)
      await other.close()
    }
  }

  const rtt = await node.services.ping.ping(conn.remotePeer, { signal })
  log(`ping over /webrtc successful, rtt ${rtt}ms`)
  await node.stop()
  return rtt
}

async function runListener (signal) {
  if (RELAY_ADDR === undefined) {
    throw new Error('listener mode needs RELAY_ADDR (the js peer does not embed a relay server)')
  }
  const relayAddr = multiaddr(RELAY_ADDR)
  const node = await createNode({ listen: ['/p2p-circuit', '/webrtc'] })
  log(`listener peer id ${node.peerId.toString()}, connecting to relay ${relayAddr.toString()}`)

  await node.dial(relayAddr, { signal })

  // Wait for the circuit reservation to surface a /webrtc listen address.
  let advertised
  for (;;) {
    signal.throwIfAborted()
    advertised = node.getMultiaddrs().find((ma) => {
      const protos = protoNames(ma)
      return protos.includes('webrtc') && protos.includes('p2p-circuit')
    })
    if (advertised !== undefined) {
      break
    }
    await sleep(250, undefined, { signal })
  }

  await publishAddr(advertised)
  console.log(`LISTENING_ON=${advertised.toString()}`)
  log('listener ready, address published')

  // Keep the process alive until the harness kills it.
  await new Promise(() => {})
}

async function main () {
  const rawMode = process.argv[2] ?? process.env.MODE
  if (rawMode === undefined) {
    throw new Error('pass a mode as the first argument or via MODE: listener | dialer')
  }
  const mode = rawMode.replace(/^--/, '').toLowerCase()
  const signal = AbortSignal.timeout(TEST_TIMEOUT_SECS * 1000)

  switch (mode) {
    case 'dialer':
    case 'dial': {
      const rtt = await runDialer(signal)
      console.log(`JS_INTEROP_OK rtt_ms=${rtt}`)
      process.exit(0)
      break
    }
    case 'listener':
    case 'listen':
      await runListener(signal)
      break
    default:
      throw new Error(`unknown mode "${mode}", expected listener | dialer`)
  }
}

function describeError (err) {
  if (err == null) {
    return 'unknown error'
  }
  if (err.name === 'TimeoutError' || err.name === 'AbortError') {
    return `timed out after ${TEST_TIMEOUT_SECS}s`
  }
  if (err instanceof AggregateError) {
    return `${err.message}: [${err.errors.map(describeError).join('; ')}]`
  }
  // DOM ErrorEvents (e.g. websocket failures) stringify uselessly.
  if (err.error != null) {
    return describeError(err.error)
  }
  return err.stack ?? err.message ?? String(err)
}

try {
  await main()
} catch (err) {
  console.log(`JS_INTEROP_FAIL: ${describeError(err)}`)
  process.exit(1)
}
