import { resolve } from 'node:path'

export function loadConfig(env = process.env) {
  const publicUrl = new URL(env.PUBLIC_URL ?? 'http://127.0.0.1:8080')
  const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(publicUrl.hostname)
  // Passwords, session cookies and secret links must never cross a network unencrypted.
  if (publicUrl.protocol !== 'https:' && !isLocal) {
    throw new Error(`PUBLIC_URL must use https:// (got ${publicUrl.origin}). Plain http is only allowed on localhost.`)
  }
  // Optional sign-in for everyone at an OIDC provider such as Pocket ID.
  let oidc = null
  let memberKey = null
  if (env.OIDC_ISSUER) {
    const issuer = new URL(env.OIDC_ISSUER)
    if (issuer.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(issuer.hostname)) {
      throw new Error('OIDC_ISSUER must use https://')
    }
    if (!env.OIDC_CLIENT_ID) throw new Error('OIDC_ISSUER is set, so OIDC_CLIENT_ID is needed too')
    memberKey = Buffer.from(env.MEMBER_KEY ?? '', 'base64')
    if (memberKey.length !== 32) {
      throw new Error('OIDC_ISSUER is set, so MEMBER_KEY must be 32 random bytes in base64. Make one with: openssl rand -base64 32')
    }
    oidc = {
      issuer: env.OIDC_ISSUER.replace(/\/+$/, ''),
      clientId: env.OIDC_CLIENT_ID,
      clientSecret: env.OIDC_CLIENT_SECRET || null,
      allowedGroup: env.OIDC_ALLOWED_GROUP || null,
      name: env.OIDC_NAME || 'single sign-on',
    }
  }
  return {
    origin: publicUrl.origin,
    oidc,
    memberKey,
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
    rsvgPath: env.RSVG_PATH ?? 'rsvg-convert',
    // Videos over this size get a smaller copy for Discord embeds. 0 turns copies off.
    discordCopies: env.DISCORD_COPIES !== '0',
    discordCopyOverBytes: Number(env.DISCORD_COPY_OVER_MB ?? 45) * 1024 ** 2,
  }
}
