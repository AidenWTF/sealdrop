import { createServer, request } from 'node:http'
import { mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { loadConfig } from '../src/config.js'
import { totpCode } from '../src/crypto.js'
import { loadOwner, newSecrets, writeOwner } from '../src/owner.js'
import { createApp } from '../src/server.js'

export const PASSWORD = 'correct horse battery staple'
const FAST_KDF = { N: 2 ** 12, r: 8, p: 1 }

const freePort = () => new Promise((resolve) => {
  const probe = createServer().listen(0, '127.0.0.1', () => {
    const { port } = probe.address()
    probe.close(() => resolve(port))
  })
})

export async function makeOwnerDir(t) {
  const dataDir = await mkdtemp(join(tmpdir(), 'sealdrop-test-'))
  t.after(() => rm(dataDir, { recursive: true, force: true }))
  const secrets = newSecrets()
  await writeOwner(dataDir, PASSWORD, secrets, FAST_KDF)
  return { dataDir, secrets }
}

export async function startApp(t, env = {}, existing = null) {
  const { dataDir, secrets } = existing ?? await makeOwnerDir(t)
  const port = await freePort()
  const config = loadConfig({
    PUBLIC_URL: `http://127.0.0.1:${port}`, PORT: String(port), DATA_DIR: dataDir,
    FFMPEG_PATH: '/nonexistent/ffmpeg', FFPROBE_PATH: '/nonexistent/ffprobe', ...env,
  })
  const clock = { ms: Date.now() }
  const events = []
  const app = createApp(config, {
    owner: await loadOwner(dataDir),
    now: () => clock.ms,
    log: (line) => events.push(JSON.parse(line)),
  })
  await app.init()
  await new Promise((resolve) => app.server.listen(port, '127.0.0.1', resolve))
  t.after(async () => {
    await app.embeds.idle() // no background copy may outlive the test and its data directory
    await new Promise((resolve) => {
      app.server.closeAllConnections()
      app.server.close(resolve)
    })
  })
  const base = `http://127.0.0.1:${port}`
  const ctx = { app, config, clock, events, dataDir, secrets, base, port }

  ctx.currentCode = () => totpCode(secrets.totpSecret, Math.floor(clock.ms / 30_000))
  ctx.tryLogin = (password, code, headers = {}) => fetch(`${base}/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: { Origin: base, 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams({ password, code }),
  })
  ctx.login = async () => {
    clock.ms += 90_000 // a fresh TOTP step, since every code is single use
    const response = await ctx.tryLogin(PASSWORD, ctx.currentCode())
    if (response.status !== 303) throw new Error(`login failed: ${response.status}`)
    const cookie = response.headers.getSetCookie().find((c) => c.includes('_session=')).split(';')[0]
    const home = await (await fetch(`${base}/`, { headers: { Cookie: cookie } })).text()
    const csrf = /name="csrf-token" content="([^"]+)"/.exec(home)[1]
    return { cookie, csrf, ownerHeaders: { Cookie: cookie, 'X-CSRF-Token': csrf, Origin: base } }
  }
  ctx.upload = async (session, body, name = 'file.bin') => {
    const response = await fetch(`${base}/api/upload`, {
      method: 'POST',
      headers: { ...session.ownerHeaders, 'X-File-Name': encodeURIComponent(name), 'Content-Type': 'application/octet-stream' },
      body,
    })
    if (response.status !== 201) throw new Error(`upload failed: ${response.status}`)
    return response.json()
  }
  ctx.storedFiles = async () => (await readdir(join(dataDir, 'files'))).length
  ctx.tmpEntries = async () => (await readdir(join(dataDir, 'tmp'))).length
  // Raw HTTP for what fetch refuses to send: unnormalised paths and custom Host headers.
  ctx.raw = (method, path, headers = {}, body) => new Promise((resolve) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers: { Connection: 'close', ...headers } }, (res) => {
      const pieces = []
      res.on('data', (p) => pieces.push(p))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(pieces).toString() }))
      res.on('error', () => resolve({ status: res.statusCode, headers: res.headers, body: '' }))
    })
    req.on('error', () => resolve({ status: 0, headers: {}, body: '' }))
    req.end(body)
  })
  return ctx
}

export async function allDiskFiles(dir) {
  const found = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) found.push(...await allDiskFiles(path))
    else found.push({ path, bytes: await readFile(path), mode: (await stat(path)).mode & 0o777 })
  }
  return found
}
