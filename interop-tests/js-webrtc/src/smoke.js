/**
 * Startup smoke test: proves node can load @libp2p/webrtc (via the
 * node-datachannel polyfill) and assemble the full interop stack without
 * throwing. Prints `JS_SMOKE_OK` and exits 0 on success.
 */
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

const node = await createLibp2p({
  addresses: { listen: [] },
  transports: [webSockets(), circuitRelayTransport(), webRTC()],
  connectionEncrypters: [noise()],
  streamMuxers: [yamux()],
  connectionGater: { denyDialMultiaddr: () => false },
  services: { identify: identify(), ping: ping() }
})

console.error(`peer id: ${node.peerId.toString()}`)
console.error(`RTCPeerConnection: ${typeof globalThis.RTCPeerConnection}`)
await node.stop()
console.log('JS_SMOKE_OK')
process.exit(0)
