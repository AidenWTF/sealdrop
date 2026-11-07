import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { Auth, ABSOLUTE_LIMIT } from './auth.js'
import { TOKEN_PATTERN } from './crypto.js'
import { createEmbedQueue } from './embeds.js'
import { PREVIEW_BYTES, decodePreview } from './textview.js'
import { attachmentHeader, cleanFileName, sendBytes } from './http.js'
import { analyze, sniff } from './media.js'
import { Store } from './store.js'
import { dashboardPage, loginPage, notFoundPage, paths, sharePage } from './views.js'

const staticFile = (name, type) => ({
  body: readFileSync(new URL(`../public/${name}`, import.meta.url)),
  type,
})

const ROBOTS = 'User-agent: Discordbot\nAllow: /file/\nAllow: /raw/\nAllow: /thumb/\nAllow: /embed/\n\nUser-agent: *\nDisallow: /\n'

const htmlPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
// Share pages run no script at all.
const sharePolicy = "default-src 'none'; style-src 'self'; img-src 'self'; media-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
// Media allowlisted by its bytes also runs no script. It can't use the sandbox directive,
// because a sandboxed page has an opaque origin and 'self' would then block its own video.
const mediaPolicy = "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; base-uri 'none'"
// Everything else is arbitrary content and only ever downloads.
const downloadPolicy = "default-src 'none'; sandbox"

export function createApp(config, { owner, now = Date.now, log = console.log }) {
  const audit = (event, fields = {}) => log(JSON.stringify({ at: new Date(now()).toISOString(), event, ...fields }))
  const store = new Store(config.dataDir)
  const auth = new Auth({ owner, config, audit, now })
  const embeds = createEmbedQueue({ store, config, audit })
  const queueEmbed = (file) => embeds.consider(file).catch((err) => audit('embed_error', { code: err.code ?? 'unknown' }))
  const assets = {
    'style.css': staticFile('style.css', 'text/css; charset=utf-8'),
    'app.js': staticFile('app.js', 'text/javascript; charset=utf-8'),
  }

  const clientIp = (req) => {
    if (config.trustProxy) {
      // The rightmost entry is the one the trusted proxy added; earlier ones are client-supplied.
      const forwarded = String(req.headers['x-forwarded-for'] ?? '').split(',').pop().trim()
      if (forwarded) return forwarded
    }
    return req.socket.remoteAddress ?? 'unknown'
  }

  const sendHtml = (res, status, html, policy = htmlPolicy) => {
    res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': policy })
    res.end(html)
  }

  // Under no-referrer, browsers send "Origin: null" on form posts, which the login's origin
  // check rightly refuses. The login page has no secret in its URL, so it can use same-origin.
  const sendLogin = (res, status, error) => {
    res.setHeader('Referrer-Policy', 'same-origin')
    sendHtml(res, status, loginPage(config, error))
  }

  const sendJson = (res, status, value) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Security-Policy': "default-src 'none'" })
    res.end(JSON.stringify(value))
  }

  // Answers, then cuts the connection, so a refused client can't keep sending data.
  const refuse = (req, res, status, error) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', Connection: 'close' })
    res.end(JSON.stringify({ error }), () => req.destroy())
  }

  const describe = ({ token, meta }) => ({
    token,
    name: meta.name,
    size: meta.size,
    kind: meta.kind,
    createdAt: meta.createdAt,
    pageUrl: config.origin + paths.page(token, meta.name),
    rawUrl: config.origin + paths.raw(token, meta.name),
    thumbUrl: meta.hasThumb ? paths.thumb(token) : meta.kind === 'image' ? paths.raw(token, meta.name) : null,
  })

  async function readBody(req, limit) {
    const pieces = []
    let total = 0
    const timer = setTimeout(() => req.destroy(), 10_000)
    try {
      for await (const piece of req) {
        total += piece.length
        if (total > limit) return null
        pieces.push(piece)
      }
      return Buffer.concat(pieces).toString('utf8')
    } finally {
      clearTimeout(timer)
    }
  }

  async function handleHome(req, res) {
    const session = auth.authenticate(req)
    if (session) sendHtml(res, 200, dashboardPage(config, session))
    else sendLogin(res, 200)
  }

  async function handleLogin(req, res) {
    if (!auth.sameOrigin(req)) return refuse(req, res, 403, 'forbidden')
    if ((req.headers['content-type'] ?? '').split(';')[0].trim() !== 'application/x-www-form-urlencoded') {
      return refuse(req, res, 415, 'unsupported')
    }
    const body = await readBody(req, 4096)
    if (body === null) return refuse(req, res, 413, 'too large')
    const form = new URLSearchParams(body)
    const result = await auth.login({ password: form.get('password'), code: form.get('code'), ip: clientIp(req), req })
    if (result.status === 200) {
      const cookies = [auth.sessionCookie(result.cookie, ABSOLUTE_LIMIT)]
      if (result.newDevice) cookies.push(auth.deviceCookie(result.newDevice))
      res.writeHead(303, { Location: '/', 'Set-Cookie': cookies })
      return res.end()
    }
    const message = result.status === 429 ? 'Too many attempts. Try again later.' : 'Those details are not correct.'
    sendLogin(res, result.status, message)
  }

  async function handleLogout(req, res) {
    auth.logout(req)
    audit('logout', { ip: clientIp(req) })
    res.writeHead(204, { 'Set-Cookie': auth.sessionCookie('', 0) })
    res.end()
  }

  async function handleList(req, res, { session }) {
    const files = await store.list(session.masterKey)
    // Picks up copies still missing after a restart, and for files uploaded before copies existed.
    for (const file of files) queueEmbed(file)
    sendJson(res, 200, { files: files.map(describe) })
  }

  async function handleUpload(req, res, { session }) {
    if (Number(req.headers['content-length'] ?? 0) > config.maxUploadBytes) return refuse(req, res, 413, 'file too large')
    const upload = await store.beginUpload()
    try {
      for await (const piece of req) {
        if (upload.size + piece.length > config.maxUploadBytes) return refuse(req, res, 413, 'file too large')
        await upload.write(piece)
        session.lastSeen = auth.now()
      }
      if (!req.complete) throw new Error('upload interrupted')
      await upload.finishData()
      const { thumb, ...media } = await analyze(sniff(upload.head), upload.reader(), upload.size, config)
      // Checked again at the last moment: signing out during an upload discards it.
      if (session.revoked) return refuse(req, res, 401, 'unauthorized')
      const meta = {
        ...media,
        name: cleanFileName(req.headers['x-file-name']),
        size: upload.size,
        md5: upload.md5,
        createdAt: auth.now(),
        hasThumb: Boolean(thumb),
      }
      const { token } = upload
      await upload.commit(meta, thumb, session.masterKey)
      audit('upload_ok', { ip: clientIp(req), bytes: meta.size })
      sendJson(res, 201, describe({ token, meta }))
      store.load(token).then((stored) => stored && queueEmbed(stored)).catch(() => {})
    } catch (err) {
      if (req.destroyed && !req.complete) return
      audit('upload_error', { code: err.code ?? 'unknown' })
      if (!res.headersSent) sendJson(res, err.code === 'ENOSPC' ? 507 : 500, { error: 'upload failed' })
    } finally {
      await upload.abort()
    }
  }

  async function handleDelete(req, res, { match }) {
    const removed = await store.remove(match.groups.token)
    if (removed) audit('delete', { ip: clientIp(req) })
    sendJson(res, removed ? 200 : 404, { removed })
  }

  // The start of a text file, for its preview.
  async function readPreview(file) {
    const length = Math.min(file.meta.size, PREVIEW_BYTES)
    if (length === 0) return { text: '', truncated: false }
    const pieces = []
    for await (const piece of file.read(0, length - 1)) pieces.push(piece)
    const truncated = file.meta.size > length
    return { text: decodePreview(Buffer.concat(pieces), truncated), truncated, bytes: length }
  }

  async function handleShare(req, res, { match }) {
    const file = await store.load(match.groups.token)
    if (!file) return sendHtml(res, 404, notFoundPage(config))
    const embed = ['video', 'audio'].includes(file.meta.kind) ? await store.embed(file) : null
    const text = file.meta.kind === 'text' ? await readPreview(file) : null
    const view = new URL(req.url, 'http://x').searchParams.get('view') === 'source' ? 'source' : 'rendered'
    sendHtml(res, 200, sharePage(config, file, { embed: embed?.read ? embed : null, text, view }), sharePolicy)
  }

  async function sendFile(req, res, token, forceDownload) {
    const file = await store.load(token)
    if (!file) return sendHtml(res, 404, notFoundPage(config))
    // Text is previewed on the share page, but its direct link still downloads: served
    // inline, an HTML or SVG file would be one browser quirk away from running here.
    const previewable = ['image', 'video', 'audio'].includes(file.meta.kind)
    const asDownload = forceDownload || !previewable
    try {
      await sendBytes(req, res, {
        size: file.meta.size,
        read: file.read,
        headers: {
          'Content-Type': previewable ? file.meta.type : 'application/octet-stream',
          'Content-Disposition': attachmentHeader(asDownload ? 'attachment' : 'inline', file.meta.name),
          'Content-Security-Policy': previewable ? mediaPolicy : downloadPolicy,
          'Cross-Origin-Resource-Policy': 'cross-origin',
        },
      })
    } catch (err) {
      if (err.code !== 'ERR_STREAM_PREMATURE_CLOSE') audit('integrity_failure', { id: file.keys.id })
      res.destroy()
    }
  }

  // The Discord-sized copy. Linked only from the share page's embed tags.
  async function handleEmbed(req, res, { match }) {
    const file = await store.load(match.groups.token)
    const embed = file && await store.embed(file)
    if (!embed?.read) return sendHtml(res, 404, notFoundPage(config))
    try {
      await sendBytes(req, res, {
        size: embed.size,
        read: embed.read,
        headers: {
          'Content-Type': 'video/mp4',
          'Content-Disposition': 'inline',
          'Content-Security-Policy': mediaPolicy,
          'Cross-Origin-Resource-Policy': 'cross-origin',
        },
      })
    } catch (err) {
      if (err.code !== 'ERR_STREAM_PREMATURE_CLOSE') audit('integrity_failure', { id: file.keys.id })
      res.destroy()
    }
  }

  const handleRaw = (req, res, { match }) => sendFile(req, res, match.groups.token, false)
  const handleDownload = (req, res, { match }) => sendFile(req, res, match.groups.token, true)

  async function handleThumb(req, res, { match }) {
    const file = await store.load(match.groups.token)
    const thumb = file && await store.thumb(file)
    if (!thumb) return sendHtml(res, 404, notFoundPage(config))
    await sendBytes(req, res, {
      size: thumb.length,
      read: async function* (start, end) { yield thumb.subarray(start, end + 1) },
      headers: { 'Content-Type': 'image/jpeg', 'Content-Security-Policy': mediaPolicy, 'Cross-Origin-Resource-Policy': 'cross-origin' },
    })
  }

  async function handleStatic(req, res, { match }) {
    const asset = assets[match.groups.name]
    res.writeHead(200, { 'Content-Type': asset.type, 'Cache-Control': 'no-cache', 'Content-Length': asset.body.length })
    res.end(req.method === 'HEAD' ? undefined : asset.body)
  }

  async function handleRobots(req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end(ROBOTS)
  }

  const READ = ['GET', 'HEAD']
  const TOKEN = `(?<token>${TOKEN_PATTERN})`

  // The complete surface of the site. Anything not listed is a 404. "owner" routes pass the
  // authentication gate in dispatch() before their handler runs; "csrf" adds the same-origin
  // and CSRF token checks. Only POST /login accepts data without being signed in.
  const routes = [
    { methods: READ, path: /^\/$/, access: 'public', handler: handleHome },
    { methods: ['POST'], path: /^\/login$/, access: 'public', handler: handleLogin },
    { methods: READ, path: /^\/robots\.txt$/, access: 'public', handler: handleRobots },
    { methods: READ, path: /^\/static\/(?<name>style\.css|app\.js)$/, access: 'public', handler: handleStatic },
    { methods: READ, path: new RegExp(`^/file/${TOKEN}(/[^/]*)?$`), access: 'public', handler: handleShare },
    { methods: READ, path: new RegExp(`^/raw/${TOKEN}(/[^/]*)?$`), access: 'public', handler: handleRaw },
    { methods: READ, path: new RegExp(`^/download/${TOKEN}(/[^/]*)?$`), access: 'public', handler: handleDownload },
    { methods: READ, path: new RegExp(`^/thumb/${TOKEN}\\.jpg$`), access: 'public', handler: handleThumb },
    { methods: READ, path: new RegExp(`^/embed/${TOKEN}\\.mp4$`), access: 'public', handler: handleEmbed },
    { methods: ['POST'], path: /^\/logout$/, access: 'owner', csrf: true, handler: handleLogout },
    { methods: ['GET'], path: /^\/api\/files$/, access: 'owner', handler: handleList },
    { methods: ['POST'], path: /^\/api\/upload$/, access: 'owner', csrf: true, handler: handleUpload },
    { methods: ['DELETE'], path: new RegExp(`^/api/files/${TOKEN}$`), access: 'owner', csrf: true, handler: handleDelete },
  ]
  for (const route of routes) {
    if (route.access !== 'public' && route.access !== 'owner') throw new Error('every route must declare its access')
    if (route.access === 'owner' && !route.methods.every((m) => READ.includes(m)) && !route.csrf) {
      throw new Error('every owner route that changes state must require CSRF protection')
    }
  }

  async function dispatch(req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive')
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    res.setHeader('Cache-Control', 'no-store')
    if (config.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

    if (req.headers.host !== config.host) return refuse(req, res, 421, 'wrong host')
    // No read-only route takes a body. Accepting one would let a client hold a connection
    // open forever by sending it a byte at a time.
    if ((req.method === 'GET' || req.method === 'HEAD')
      && (Number(req.headers['content-length'] ?? 0) > 0 || req.headers['transfer-encoding'])) {
      return refuse(req, res, 400, 'bad request')
    }

    const [path] = req.url.split('?', 1)
    for (const route of routes) {
      const match = route.path.exec(path)
      if (!match || !route.methods.includes(req.method)) continue
      let session = null
      if (route.access === 'owner') {
        session = auth.authenticate(req)
        if (!session) {
          audit('owner_route_denied', { ip: clientIp(req), route: path.startsWith('/api/upload') ? 'upload' : 'other', reason: 'no session' })
          return refuse(req, res, 401, 'unauthorized')
        }
        if (route.csrf && !auth.checkCsrf(req, session)) {
          audit('owner_route_denied', { ip: clientIp(req), route: path.startsWith('/api/upload') ? 'upload' : 'other', reason: 'csrf' })
          return refuse(req, res, 403, 'forbidden')
        }
      }
      return route.handler(req, res, { session, match })
    }
    if (req.method === 'GET' || req.method === 'HEAD') return sendHtml(res, 404, notFoundPage(config))
    refuse(req, res, 404, 'not found')
  }

  const server = createServer((req, res) => {
    dispatch(req, res).catch((err) => {
      audit('request_error', { code: err.code ?? 'unknown' })
      if (!res.headersSent) sendJson(res, 500, { error: 'server error' })
      else res.destroy()
    })
  })
  // Uploads can run for hours, so the whole-request limit is off. Only the owner's uploads
  // can run long: anonymous bodies are refused in dispatch(), and login has its own short limit.
  server.requestTimeout = 0
  server.headersTimeout = 20_000
  server.keepAliveTimeout = 5_000
  server.timeout = 300_000

  return { server, store, auth, embeds, routes, init: async () => { await store.init(); await auth.init(); await embeds.init() } }
}
