import { mkdir } from 'node:fs/promises'
import { loadConfig } from './config.js'
import { ffmpegAvailable } from './media.js'
import { loadOwner, ownerPath } from './owner.js'
import { createApp } from './server.js'

process.umask(0o077)
const config = loadConfig()
await mkdir(config.dataDir, { recursive: true, mode: 0o700 })

let owner
try {
  owner = await loadOwner(config.dataDir)
} catch (err) {
  if (err.code !== 'ENOENT') throw err
  console.error(`No owner found at ${ownerPath(config.dataDir)}. Run "npm run setup" first.`)
  process.exit(1)
}

const app = createApp(config, { owner })
await app.init()
if (!await ffmpegAvailable(config)) {
  console.warn('ffmpeg/ffprobe not found: uploads still work, but video previews and sizes in embeds will be missing.')
}
app.server.listen(config.port, config.bindHost, () => {
  console.log(`${config.siteName} listening on ${config.bindHost}:${config.port}, public address ${config.origin}`)
})
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    app.server.close(() => process.exit(0))
    app.server.closeIdleConnections()
    setTimeout(() => process.exit(0), 5000).unref()
  })
}
