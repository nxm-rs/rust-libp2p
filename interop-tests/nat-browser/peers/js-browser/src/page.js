/**
 * Browser-side js-libp2p private-to-private `/webrtc` interop peer.
 *
 * Runs in stock Chrome with the native RTCPeerConnection (no node-datachannel
 * polyfill) and is driven by `driver.mjs` via playwright.
 *
 * Configuration arrives as query parameters, because a page cannot read env
 * vars:
 *
 * - `mode`: `listener` or `dialer`.
 * - `ice`: optional STUN/TURN url for the webrtc transport.
 * - `relay`: listener mode, the external Circuit Relay v2 multiaddr
 *   (including `/p2p/<relay-id>`) to reserve a slot on.
 * - `dial`: dialer mode, the listener's full
 *   `<relay>/p2p-circuit/webrtc/p2p/<id>` multiaddr.
 * - `timeout`: overall timeout in seconds (default 180).
 *
 * Results are exposed on `window` for the driver to poll:
 *
 * - `window.__status`: progress string, mirrored into the DOM.
 * - `window.__listenAddr`: the listener's advertised multiaddr.
 * - `window.__result`: `{ ok: true, rttMs }` or `{ ok: false, error }`.
 */

import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { identify } from '@libp2p/identify'
import { ping } from '@libp2p/ping'
import { webRTC } from '@libp2p/webrtc'
import { webSockets } from '@libp2p/websockets'
import { multiaddr } from '@multiformats/multiaddr'
import { createLibp2p } from 'libp2p'

const params = new URLSearchParams(window.location.search)
const MODE = params.get('mode') ?? 'listener'
const ICE_SERVER = params.get('ice') ?? undefined
const RELAY_ADDR = params.get('relay') ?? undefined
const DIAL_ADDR = params.get('dial') ?? undefined
const TIMEOUT_SECS = Number.parseInt(params.get('timeout') ?? '180', 10)

function status (text) {
  window.__status = text
  document.getElementById('status').textContent = text
  console.log(`[page] ${text}`)
}

/** Protocol names of a multiaddr (multiaddr v13 dropped protoNames()). */
function protoNames (ma) {
  return ma.getComponents().map((component) => component.name)
}

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

async function runDialer (signal) {
  if (DIAL_ADDR === undefined) {
    throw new Error('dialer mode needs a ?dial=<multiaddr> query parameter')
  }
  const addr = multiaddr(DIAL_ADDR)
  const node = await createNode()
  status(`dialer peer id ${node.peerId.toString()}, dialing ${addr.toString()}`)

  const conn = await node.dial(addr, { signal })
  if (!protoNames(conn.remoteAddr).includes('webrtc')) {
    throw new Error(`dial resolved with a non-webrtc connection: ${conn.remoteAddr.toString()}`)
  }
  status(`direct /webrtc connection established: ${conn.remoteAddr.toString()}`)

  // A relayed connection to the listener may remain open after signalling.
  // Close it so the ping below can only run on the direct /webrtc connection.
  for (const other of node.getConnections(conn.remotePeer)) {
    if (other.id !== conn.id) {
      status(`closing non-webrtc connection ${other.remoteAddr.toString()}`)
      await other.close()
    }
  }

  const rtt = await node.services.ping.ping(conn.remotePeer, { signal })
  status(`ping over /webrtc successful, rtt ${rtt}ms`)
  return rtt
}

async function runListener (signal) {
  if (RELAY_ADDR === undefined) {
    throw new Error('listener mode needs a ?relay=<multiaddr> query parameter')
  }
  const relayAddr = multiaddr(RELAY_ADDR)
  const node = await createNode({ listen: ['/p2p-circuit', '/webrtc'] })
  status(`listener peer id ${node.peerId.toString()}, connecting to relay ${relayAddr.toString()}`)

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
    await new Promise((resolve) => setTimeout(resolve, 250))
  }

  window.__listenAddr = advertised.toString()
  status(`listening on ${advertised.toString()}`)
  // Keep the node alive; the driver tears the browser down.
  await new Promise(() => {})
}

function describeError (err) {
  if (err == null) {
    return 'unknown error'
  }
  if (err.name === 'TimeoutError' || err.name === 'AbortError') {
    return `timed out after ${TIMEOUT_SECS}s`
  }
  if (err instanceof AggregateError) {
    return `${err.message}: [${err.errors.map(describeError).join('; ')}]`
  }
  if (err.error != null) {
    return describeError(err.error)
  }
  return err.stack ?? err.message ?? String(err)
}

try {
  const signal = AbortSignal.timeout(TIMEOUT_SECS * 1000)
  if (MODE === 'dialer' || MODE === 'dial') {
    const rttMs = await runDialer(signal)
    window.__result = { ok: true, rttMs }
  } else {
    await runListener(signal)
  }
} catch (err) {
  const error = describeError(err)
  window.__result = { ok: false, error }
  status(`FAILED: ${error}`)
}
