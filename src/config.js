import { resolve } from 'node:path'

export function loadConfig(env = process.env) {
  const publicUrl = new URL(env.PUBLIC_URL ?? 'http://127.0.0.1:8080')
  const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(publicUrl.hostname)
  // Passwords, session cookies and secret links must never cross a network unencrypted.
  if (publicUrl.protocol !== 'https:' && !isLocal) {
    throw new Error(`PUBLIC_URL must use https:// (got ${publicUrl.origin}). Plain http is only allowed on localhost.`)
  }
  return {
    origin: publicUrl.origin,
    host: publicUrl.host,
    secure: publicUrl.protocol === 'https:',
    bindHost: env.HOST ?? '127.0.0.1',
    port: Number(env.PORT ?? 8080),
    dataDir: resolve(env.DATA_DIR ?? 'data'),
    siteName: env.SITE_NAME ?? 'SealDrop',
    trustProxy: env.TRUST_PROXY === '1',
    maxUploadBytes: Number(env.MAX_UPLOAD_GB ?? 50) * 1024 ** 3,
    ffmpegPath: env.FFMPEG_PATH ?? 'ffmpeg',
    ffprobePath: env.FFPROBE_PATH ?? 'ffprobe',
  }
}
