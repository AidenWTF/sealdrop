import { mkdir } from 'node:fs/promises'
import { createServer } from 'node:http'
import { setTimeout as sleep } from 'node:timers/promises'
import { loadConfig } from './config.js'
import { ffmpegAvailable } from './media.js'
import { loadOwner, ownerPath } from './owner.js'
import { createApp } from './server.js'

const SETUP_POLL_MS = 2000

process.umask(0o077)
const config = loadConfig()
await mkdir(config.dataDir, { recursive: true, mode: 0o700 })

// Whichever server is listening right now: the "not set up yet" placeholder, then the app.
let server = null
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    if (!server) process.exit(0)
    server.close(() => process.exit(0))
    server.closeIdleConnections()
    setTimeout(() => process.exit(0), 5000).unref()
  })
}

const listen = (target) => new Promise((resolve, reject) => {
  target.once('error', reject)
  target.listen(config.port, config.bindHost, () => resolve(target.address().port))
})

async function findOwner() {
  try {
    return await loadOwner(config.dataDir)
  } catch (err) {
    if (err.code === 'ENOENT') return null
    throw err
  }
}

// Without an owner the app has nothing to serve, but it stays up rather than exiting, so
// a container platform doesn't restart it in a loop and setup can be run inside it.
// The placeholder only ever answers 503: no web request can create the owner.
async function waitForOwner() {
  const placeholder = createServer((req, res) => {
    res.writeHead(503, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      'Retry-After': '10',
    })
    res.end(`${config.siteName} is not set up yet.\n`)
  })
  server = placeholder
  const port = await listen(placeholder)
  console.error(`No owner found at ${ownerPath(config.dataDir)}. Waiting for setup on ${config.bindHost}:${port}.`)
  console.error('Run "node src/setup.js" inside this container ("npm run setup" without Docker). The site starts by itself once setup is done.')
  let owner
  while (!(owner = await findOwner())) await sleep(SETUP_POLL_MS)
  placeholder.closeAllConnections()
  await new Promise((resolve) => placeholder.close(resolve))
  console.log('Owner found, starting.')
  return owner
}

const owner = await findOwner() ?? await waitForOwner()
const app = createApp(config, { owner })
await app.init()
if (!await ffmpegAvailable(config)) {
  console.warn('ffmpeg/ffprobe not found: uploads still work, but video previews and sizes in embeds will be missing.')
}
if (config.discordCopies && !app.embeds.enabled) {
  console.warn('/dev/shm not found: large videos get no smaller copy for Discord embeds.')
}
server = app.server
const port = await listen(app.server)
console.log(`${config.siteName} listening on ${config.bindHost}:${port}, public address ${config.origin}`)
