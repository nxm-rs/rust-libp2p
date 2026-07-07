/**
 * Drives the browser-side js-libp2p `/webrtc` interop peer (`src/page.js`,
 * bundled to `dist/bundle.js`) in stock Chrome via playwright-core.
 *
 * The driver plays the same role `wasm_ping` plays for the rust wasm peer: it
 * serves the bundle over a loopback http server, does the redis rendezvous the
 * page cannot do itself (redis speaks raw TCP), threads the STUN url and relay
 * address into the page as query parameters, and turns the page's outcome into
 * an exit code plus log lines.
 *
 * Roles, selected by the first CLI argument or the `MODE` env var:
 *
 * - `listener`: loads the page in listener mode, waits for its advertised
 *   `/p2p-circuit/webrtc` multiaddr, RPUSHes it to the `listenerAddr` redis
 *   list (rust interop harness compatible) and prints `LISTENING_ON=<addr>`.
 *   Keeps running until killed by the harness.
 * - `dialer`: BLPOPs `listenerAddr`, loads the page in dialer mode and waits
 *   for the ping result. Prints `JS_BROWSER_INTEROP_OK rtt_ms=<rtt>` and exits
 *   0 on success, `JS_BROWSER_INTEROP_FAIL: <reason>` and exits 1 otherwise.
 *
 * Environment variables:
 *
 * - `MODE`: `listener` or `dialer` (fallback when no CLI argument is given).
 * - `REDIS_ADDR` / `redis_addr`: `host:port` of the redis rendezvous.
 * - `ICE_SERVER` / `ice_server`: optional STUN/TURN url for the page.
 * - `RELAY_ADDR` / `relay_addr`: listener mode, the external relay multiaddr.
 * - `TEST_TIMEOUT_SECS`: overall timeout (default `180`).
 * - `CHROME_BIN`: Chrome executable (auto-detected otherwise).
 *
 * Browser console lines are forwarded to stdout with a `BROWSER:` prefix, so
 * the `ICE_SELECTED_PAIR` line emitted by `src/shim.js` lands in the container
 * log for `nat-browser/scripts/ice-report.sh`.
 */

import { readFile, access } from 'node:fs/promises'
import { createServer } from 'node:http'
import { extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { chromium } from 'playwright-core'
import { createClient } from 'redis'

const DIST = fileURLToPath(new URL('./dist', import.meta.url))
const MODE = (process.argv[2] ?? process.env.MODE ?? '').replace(/^--/, '').toLowerCase()
const REDIS_ADDR = process.env.REDIS_ADDR ?? process.env.redis_addr
const ICE_SERVER = process.env.ICE_SERVER ?? process.env.ice_server
const RELAY_ADDR = process.env.RELAY_ADDR ?? process.env.relay_addr
const TEST_TIMEOUT_SECS = Number.parseInt(process.env.TEST_TIMEOUT_SECS ?? '180', 10)
// The redis list key the rust interop harness uses for the listener's multiaddr.
const LISTENER_ADDR_KEY = 'listenerAddr'

const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.map': 'application/json'
}

function log (...args) {
  console.error(`[js-browser-driver ${new Date().toISOString()}]`, ...args)
}

async function findChrome () {
  const candidates = [
    process.env.CHROME_BIN,
    '/usr/bin/google-chrome',
    '/opt/google/chrome/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium'
  ].filter((c) => c != null)
  for (const candidate of candidates) {
    try {
      await access(candidate)
      return candidate
    } catch {}
  }
  throw new Error(`no Chrome executable found, tried: ${candidates.join(', ')}`)
}

/** Serves dist/ on an ephemeral loopback port; returns the base url. */
async function serveBundle () {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, 'http://localhost').pathname
    const file = path === '/' ? '/index.html' : path
    try {
      const body = await readFile(join(DIST, file))
      res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' })
      res.end(body)
    } catch {
      res.writeHead(404)
      res.end('not found')
    }
  })
  await new Promise((resolve, reject) => {
    server.on('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return `http://127.0.0.1:${server.address().port}`
}

async function connectRedis () {
  if (REDIS_ADDR === undefined) {
    throw new Error('set REDIS_ADDR (host:port) for the rendezvous')
  }
  const client = createClient({ url: `redis://${REDIS_ADDR}` })
  client.on('error', (err) => log(`redis error: ${err.message}`))
  await client.connect()
  return client
}

async function openPage (browser, query) {
  const baseUrl = await serveBundle()
  const page = await browser.newPage()
  page.on('console', (msg) => console.log(`BROWSER: ${msg.text()}`))
  page.on('pageerror', (err) => console.log(`BROWSER_ERROR: ${err.message}`))
  const params = new URLSearchParams(query)
  if (ICE_SERVER !== undefined) {
    params.set('ice', ICE_SERVER)
  }
  params.set('timeout', String(TEST_TIMEOUT_SECS))
  const url = `${baseUrl}/index.html?${params.toString()}`
  log(`loading ${url}`)
  await page.goto(url)
  return page
}

/** Rejects as soon as the page reports a failed result. */
function watchFailure (page) {
  return page
    .waitForFunction(() => window.__result !== undefined && window.__result.ok === false, undefined, {
      timeout: TEST_TIMEOUT_SECS * 1000
    })
    .then(async () => {
      const result = await page.evaluate(() => window.__result)
      throw new Error(result.error ?? 'page reported failure')
    })
}

async function runListener (browser) {
  if (RELAY_ADDR === undefined) {
    throw new Error('listener mode needs RELAY_ADDR')
  }
  const page = await openPage(browser, { mode: 'listener', relay: RELAY_ADDR })

  // The failure watch either rejects with the page's error, or with a
  // TimeoutError once the page survived TEST_TIMEOUT_SECS without failing.
  const failure = watchFailure(page)
  failure.catch(() => {}) // no unhandled rejection when it loses the race

  const listenAddr = await Promise.race([
    page
      .waitForFunction(() => window.__listenAddr !== undefined, undefined, {
        timeout: TEST_TIMEOUT_SECS * 1000
      })
      .then(() => page.evaluate(() => window.__listenAddr)),
    failure
  ])

  const redis = await connectRedis()
  try {
    await redis.rPush(LISTENER_ADDR_KEY, listenAddr)
  } finally {
    await redis.destroy()
  }
  console.log(`LISTENING_ON=${listenAddr}`)
  log('listener ready, address published to redis')

  // Keep the page (and the reservation) alive until the harness kills us,
  // while still surfacing a late page failure.
  try {
    await failure
  } catch (err) {
    if (err.name !== 'TimeoutError') {
      throw err
    }
  }
  await new Promise(() => {})
}

async function runDialer (browser) {
  const redis = await connectRedis()
  let dialAddr
  try {
    const result = await redis.blPop(LISTENER_ADDR_KEY, TEST_TIMEOUT_SECS)
    if (result?.element == null) {
      throw new Error(`timed out waiting for ${LISTENER_ADDR_KEY} in redis`)
    }
    dialAddr = result.element
  } finally {
    await redis.destroy()
  }
  log(`dialing ${dialAddr}`)

  const page = await openPage(browser, { mode: 'dialer', dial: dialAddr })
  await page.waitForFunction(() => window.__result !== undefined, undefined, {
    timeout: TEST_TIMEOUT_SECS * 1000
  })
  const result = await page.evaluate(() => window.__result)
  if (result.ok !== true) {
    throw new Error(result.error ?? 'page reported failure')
  }
  return result.rttMs
}

async function main () {
  if (MODE !== 'listener' && MODE !== 'listen' && MODE !== 'dialer' && MODE !== 'dial') {
    throw new Error(`pass a mode (listener | dialer) as the first argument or via MODE, got "${MODE}"`)
  }
  const executablePath = await findChrome()
  log(`launching ${executablePath}`)
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage']
  })
  try {
    if (MODE === 'dialer' || MODE === 'dial') {
      const rttMs = await runDialer(browser)
      console.log(`JS_BROWSER_INTEROP_OK rtt_ms=${rttMs}`)
    } else {
      await runListener(browser)
    }
  } finally {
    await browser.close().catch(() => {})
  }
}

function describeError (err) {
  if (err == null) {
    return 'unknown error'
  }
  if (err.name === 'TimeoutError') {
    return `timed out after ${TEST_TIMEOUT_SECS}s`
  }
  return err.stack ?? err.message ?? String(err)
}

try {
  await main()
  process.exit(0)
} catch (err) {
  console.log(`JS_BROWSER_INTEROP_FAIL: ${describeError(err)}`)
  process.exit(1)
}
