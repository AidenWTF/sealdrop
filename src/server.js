import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { Auth, ABSOLUTE_LIMIT } from './auth.js'
import { TOKEN_PATTERN } from './crypto.js'
import { createEmbedQueue } from './embeds.js'
import { MetadataError, cleanJpeg } from './jpegclean.js'
import { PREVIEW_BYTES, decodePreview } from './textview.js'
import { Oidc, OidcError } from './oidc.js'
import { SHORT_PATTERN, memberMasterKey, sha256 } from './crypto.js'
import { Links, cleanTarget } from './links.js'
import { attachmentHeader, cleanFileName, sendBytes } from './http.js'
import { analyze, sniff } from './media.js'
import { Store } from './store.js'
import { dashboardPage, loginPage, notFoundPage, paths, sharePage } from './views.js'

const staticFile = (name, type) => ({
  body: readFileSync(new URL(`../public/${name}`, import.meta.url)),
  type,
})

const ROBOTS = 'User-agent: Discordbot\nAllow: /file/\nAllow: /raw/\nAllow: /thumb/\nAllow: /embed/\nAllow: /s/\n\nUser-agent: *\nDisallow: /\n'

const htmlPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; media-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
// Share pages run no script at all.
const sharePolicy = "default-src 'none'; style-src 'self'; img-src 'self'; media-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
// Media allowlisted by its bytes also runs no script. It can't use the sandbox directive,
// because a sandboxed page has an opaque origin and 'self' would then block its own video.
const mediaPolicy = "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; base-uri 'none'"
// Everything else is arbitrary content and only ever downloads.
const downloadPolicy = "default-src 'none'; sandbox"

export function createApp(config, { owner, now = Date.now, log = console.log, oidcFetch = fetch }) {
  const audit = (event, fields = {}) => log(JSON.stringify({ at: new Date(now()).toISOString(), event, ...fields }))
  const store = new Store(config.dataDir)
  const auth = new Auth({ owner, config, audit, now })
  const embeds = createEmbedQueue({ store, config, audit })
  const links = new Links(config.dataDir)
  // Wrong short link codes per IP. Codes can't be found by trying, and this keeps it so.
  const shortMisses = new Map()
  const SHORT_MISS_LIMIT = 30
  const SHORT_MISS_WINDOW = 15 * 60_000
  const oidc = config.oidc && new Oidc({ ...config.oidc, redirectUri: `${config.origin}/oidc/callback`, now, fetchFn: oidcFetch })
  const oidcCookieName = `${config.secure ? '__Host-' : ''}sealdrop_oidc`
  const queueEmbed = (file) => embeds.consider(file).catch((err) => audit('embed_error', { code: err.code ?? 'unknown' }))
  const assets = {
    'style.css': staticFile('style.css', 'text/css; charset=utf-8'),
    'app.js': staticFile('app.js', 'text/javascript; charset=utf-8'),
    'login.js': staticFile('login.js', 'text/javascript; charset=utf-8'),
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
    sendHtml(res, status, loginPage(config, error, { ...auth.hints, oidc: config.oidc?.name ?? null }))
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
    expiresAt: meta.expiresAt ?? null,
    maxDownloads: meta.maxDownloads ?? null,
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
    const body = await readBody(req, 16384)
    if (body === null) return refuse(req, res, 413, 'too large')
    const form = new URLSearchParams(body)
    let passkey = null
    if (form.get('passkey')) {
      try {
        passkey = JSON.parse(form.get('passkey'))
      } catch {
        passkey = 'invalid' // fails like any other wrong answer
      }
    }
    const result = await auth.login({ password: form.get('password'), code: form.get('code'), passkey, ip: clientIp(req), req })
    if (result.status === 200) {
      const cookies = [auth.sessionCookie(result.cookie, ABSOLUTE_LIMIT)]
      if (result.newDevice) cookies.push(auth.deviceCookie(result.newDevice))
      res.writeHead(303, { Location: '/', 'Set-Cookie': cookies })
      return res.end()
    }
    const message = result.status === 429 ? 'Too many attempts. Try again later.' : 'Those details are not correct.'
    sendLogin(res, result.status, message)
  }

  const handleLoginChallenge = (req, res) => sendJson(res, 200, auth.loginChallenge())

  const shortUrl = (code) => `${config.origin}/s/${code}`

  async function handleShortRedirect(req, res, { match }) {
    const ip = clientIp(req)
    const time = now()
    const misses = (shortMisses.get(ip) ?? []).filter((at) => time - at < SHORT_MISS_WINDOW)
    if (misses.length >= SHORT_MISS_LIMIT) {
      audit('short_blocked', { ip })
      res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '900' })
      return res.end('Too many unknown short links. Try again later.\n')
    }
    const target = await links.resolve(match.groups.code)
    if (!target) {
      if (shortMisses.size > 10_000) shortMisses.clear()
      shortMisses.set(ip, [...misses, time])
      return sendHtml(res, 404, notFoundPage(config))
    }
    res.writeHead(302, { Location: target.url, 'Content-Type': 'text/plain; charset=utf-8' })
    res.end(req.method === 'HEAD' ? undefined : `Redirecting to ${target.url}\n`)
  }

  async function handleListLinks(req, res, { session }) {
    const found = await links.list(session.masterKey)
    sendJson(res, 200, { links: found.map((l) => ({ ...l, shortUrl: shortUrl(l.code) })) })
  }

  async function handleCreateLink(req, res, { session }) {
    const body = await readJson(req, 8192)
    const url = cleanTarget(body?.url)
    if (!url) return sendJson(res, 400, { error: 'Use a full web address starting with https:// or http://.' })
    const created = await links.create(url, session.masterKey, now())
    audit('short_created', { ip: clientIp(req) })
    sendJson(res, 201, { ...created, shortUrl: shortUrl(created.code) })
  }

  async function handleDeleteLink(req, res, { session, match }) {
    const removed = await links.remove(match.groups.code, session.masterKey)
    sendJson(res, removed ? 200 : 404, { removed })
  }

  // Sign-in through the OIDC provider. The cookie ties the provider's answer to the browser
  // that asked, and is Lax because that answer arrives as a navigation from another site.
  const oidcCookie = (value, maxAge) =>
    `${oidcCookieName}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${config.secure ? '; Secure' : ''}`

  async function handleOidcLogin(req, res) {
    if (!oidc) return sendHtml(res, 404, notFoundPage(config))
    let started
    try {
      started = await oidc.start()
    } catch (err) {
      audit('oidc_error', { reason: err.message })
      return sendLogin(res, 502, `${config.oidc.name} can't be reached right now.`)
    }
    res.writeHead(303, { Location: started.url, 'Set-Cookie': oidcCookie(started.browser, 600) })
    res.end()
  }

  async function handleOidcCallback(req, res) {
    if (!oidc) return sendHtml(res, 404, notFoundPage(config))
    const query = new URL(req.url, config.origin).searchParams
    let person
    try {
      if (query.get('error')) throw new OidcError(`provider said ${query.get('error').slice(0, 60)}`)
      person = await oidc.finish({ code: query.get('code'), state: query.get('state'), browser: auth.cookieValue(req, oidcCookieName) })
    } catch (err) {
      audit('oidc_refused', { ip: clientIp(req), reason: err instanceof OidcError ? err.message : 'error' })
      res.setHeader('Set-Cookie', oidcCookie('', 0))
      const message = err.message === 'not in the allowed group'
        ? 'Your account is not allowed to use this site.'
        : `Signing in with ${config.oidc.name} didn't work. Try again.`
      return sendLogin(res, 403, message)
    }
    const member = { id: sha256(`member:${person.sub}`).slice(0, 16), name: person.name.slice(0, 80) }
    const cookie = auth.createSession({ masterKey: memberMasterKey(config.memberKey, person.sub), member })
    audit('login_ok', { ip: clientIp(req), method: 'oidc', member: member.id })
    // A same-site step to the dashboard, so the browser sends the new Strict session cookie.
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'none'",
      'Set-Cookie': [auth.sessionCookie(cookie, ABSOLUTE_LIMIT), oidcCookie('', 0)],
    })
    res.end('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/"><title>Signing in</title><p>Signing in… <a href="/">Continue</a></p>')
  }

  // A small JSON body from the signed-in owner, or null.
  async function readJson(req, limit = 16384) {
    if ((req.headers['content-type'] ?? '').split(';')[0].trim() !== 'application/json') return null
    const body = await readBody(req, limit)
    if (body === null) return null
    try {
      return JSON.parse(body)
    } catch {
      return null
    }
  }

  const handlePasskeys = async (req, res, { session }) => sendJson(res, 200, await auth.passkeySettings(session))
  const handlePasskeyOptions = async (req, res, { session }) => sendJson(res, 200, await auth.registrationOptions(session))

  async function handleAddPasskey(req, res, { session }) {
    const body = await readJson(req)
    if (!body) return refuse(req, res, 400, 'bad request')
    try {
      await auth.addPasskey(session, body)
    } catch (err) {
      audit('passkey_add_failed', { ip: clientIp(req), reason: err.message })
      return sendJson(res, 400, { error: 'That passkey could not be added.' })
    }
    audit('passkey_added', { ip: clientIp(req) })
    sendJson(res, 201, await auth.passkeySettings(session))
  }

  async function handleRemovePasskey(req, res, { session, match }) {
    const removed = await auth.removePasskey(session, match.groups.id)
    if (removed) audit('passkey_removed', { ip: clientIp(req) })
    sendJson(res, removed ? 200 : 404, await auth.passkeySettings(session))
  }

  async function handleCodesSetting(req, res, { session }) {
    const body = await readJson(req, 1024)
    if (typeof body?.allowed !== 'boolean') return refuse(req, res, 400, 'bad request')
    if (!await auth.setCodesAllowed(session, body.allowed)) return sendJson(res, 409, { error: 'Add a passkey first.' })
    audit(body.allowed ? 'codes_enabled' : 'codes_disabled', { ip: clientIp(req) })
    sendJson(res, 200, await auth.passkeySettings(session))
  }

  async function handleLogout(req, res) {
    auth.logout(req)
    audit('logout', { ip: clientIp(req) })
    res.writeHead(204, { 'Set-Cookie': auth.sessionCookie('', 0) })
    res.end()
  }

  async function handleList(req, res, { session }) {
    const files = []
    for (const file of await store.list(session.masterKey)) {
      if (await store.expired(file, now())) {
        await store.remove(file.token)
        audit('expired', { count: 1 })
      } else files.push(file)
    }
    // Picks up copies still missing after a restart, and for files uploaded before copies existed.
    for (const file of files) queueEmbed(file)
    const described = await Promise.all(files.map(async (file) => {
      const embed = ['video', 'audio'].includes(file.meta.kind) ? await store.embed(file) : null
      return {
        ...describe(file),
        downloads: file.meta.maxDownloads ? await store.downloads(file) : undefined,
        discord: discordStatus(file, embed),
        copySize: embed?.size ?? 0,
      }
    }))
    sendJson(res, 200, {
      files: described,
      storage: {
        files: described.reduce((sum, f) => sum + f.size, 0),
        copies: described.reduce((sum, f) => sum + f.copySize, 0),
      },
    })
  }

  // How long a link lasts and how many downloads it allows, from the upload's headers.
  // Returns null for anything but the offered choices.
  const EXPIRY_CHOICES = new Set([3600, 86400, 7 * 86400, 30 * 86400])
  function uploadLimits(req) {
    const limits = {}
    const expiresIn = req.headers['x-expires-in']
    if (expiresIn !== undefined) {
      if (!/^\d+$/.test(expiresIn) || !EXPIRY_CHOICES.has(Number(expiresIn))) return null
      limits.expiresIn = Number(expiresIn)
    }
    const maxDownloads = req.headers['x-max-downloads']
    if (maxDownloads !== undefined) {
      if (!/^\d{1,4}$/.test(maxDownloads) || Number(maxDownloads) < 1 || Number(maxDownloads) > 1000) return null
      limits.maxDownloads = Number(maxDownloads)
    }
    return limits
  }

  // Where the file's Discord copy stands, for the dashboard.
  function discordStatus(file, embed) {
    if (embed?.read) return { status: 'ready' }
    if (embed?.skipped) return { status: 'skipped', reason: embed.skipped }
    if (embeds.wanted(file)) return { status: 'pending' }
    return { status: 'none' }
  }

  // A stored file whose link still works. One that has run out is deleted on the spot.
  async function loadLive(token) {
    const file = await store.load(token)
    if (!file) return null
    if (await store.expired(file, now())) {
      await store.remove(token)
      audit('expired', { count: 1 })
      return null
    }
    return file
  }

  async function handleUpload(req, res, { session }) {
    if (Number(req.headers['content-length'] ?? 0) > config.maxUploadBytes) return refuse(req, res, 413, 'file too large')
    const limits = uploadLimits(req)
    if (!limits) return refuse(req, res, 400, 'bad expiry')
    // Photos lose their location and camera details unless the owner chose to keep them.
    const source = req.headers['x-keep-metadata'] === '1' ? req : cleanJpeg(req)
    const upload = await store.beginUpload()
    try {
      for await (const piece of source) {
        if (upload.size + piece.length > config.maxUploadBytes) return refuse(req, res, 413, 'file too large')
        await upload.write(piece)
        session.lastSeen = auth.now()
      }
      if (!req.complete) throw new Error('upload interrupted')
      await upload.finishData()
      const name = cleanFileName(req.headers['x-file-name'])
      const { thumb, ...media } = await analyze(sniff(upload.head), upload.reader(), upload.size, config, { name })
      // Checked again at the last moment: signing out during an upload discards it.
      if (session.revoked) return refuse(req, res, 401, 'unauthorized')
      const meta = {
        ...media,
        name,
        size: upload.size,
        md5: upload.md5,
        createdAt: auth.now(),
        hasThumb: Boolean(thumb),
        ...(limits.expiresIn ? { expiresAt: auth.now() + limits.expiresIn * 1000 } : {}),
        ...(limits.maxDownloads ? { maxDownloads: limits.maxDownloads } : {}),
      }
      const { token } = upload
      await upload.commit(meta, thumb, session.masterKey)
      audit('upload_ok', { ip: clientIp(req), bytes: meta.size })
      sendJson(res, 201, describe({ token, meta }))
      store.load(token).then((stored) => stored && queueEmbed(stored)).catch(() => {})
    } catch (err) {
      if (req.destroyed && !req.complete) return
      if (err instanceof MetadataError) return refuse(req, res, 422, 'this photo could not be cleaned')
      audit('upload_error', { code: err.code ?? 'unknown' })
      if (!res.headersSent) sendJson(res, err.code === 'ENOSPC' ? 507 : 500, { error: 'upload failed' })
    } finally {
      await upload.abort()
    }
  }

  async function handleDelete(req, res, { session, match }) {
    // Only files in this person's own list. Everyone has their own master key.
    const file = await store.load(match.groups.token)
    if (!file || !await store.owns(file, session.masterKey)) return sendJson(res, 404, { removed: false })
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
    const file = await loadLive(match.groups.token)
    if (!file) return sendHtml(res, 404, notFoundPage(config))
    const embed = ['video', 'audio'].includes(file.meta.kind) ? await store.embed(file) : null
    const text = file.meta.kind === 'text' ? await readPreview(file) : null
    const view = new URL(req.url, 'http://x').searchParams.get('view') === 'source' ? 'source' : 'rendered'
    sendHtml(res, 200, sharePage(config, file, { embed: embed?.read ? embed : null, text, view }), sharePolicy)
  }

  async function sendFile(req, res, token, forceDownload) {
    const file = await loadLive(token)
    if (!file) return sendHtml(res, 404, notFoundPage(config))
    // A download is a fetch of the whole file. Players fetching later parts don't count.
    let last = false
    if (file.meta.maxDownloads && req.method === 'GET' && /^(bytes=0-\d*)?$/.test(req.headers.range ?? '')) {
      const count = await store.countDownload(file)
      if (count > file.meta.maxDownloads) return sendHtml(res, 404, notFoundPage(config))
      last = count === file.meta.maxDownloads
    }
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
    } finally {
      if (last) {
        await store.remove(token)
        audit('expired', { count: 1 })
      }
    }
  }

  // The Discord-sized copy. Linked only from the share page's embed tags.
  async function handleEmbed(req, res, { match }) {
    const file = await loadLive(match.groups.token)
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
    const file = await loadLive(match.groups.token)
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
    { methods: ['GET'], path: /^\/login\/challenge$/, access: 'public', handler: handleLoginChallenge },
    { methods: ['GET'], path: /^\/oidc\/login$/, access: 'public', handler: handleOidcLogin },
    { methods: ['GET'], path: /^\/oidc\/callback$/, access: 'public', handler: handleOidcCallback },
    { methods: READ, path: /^\/robots\.txt$/, access: 'public', handler: handleRobots },
    { methods: READ, path: /^\/static\/(?<name>style\.css|app\.js|login\.js)$/, access: 'public', handler: handleStatic },
    { methods: READ, path: new RegExp(`^/file/${TOKEN}(/[^/]*)?$`), access: 'public', handler: handleShare },
    { methods: READ, path: new RegExp(`^/raw/${TOKEN}(/[^/]*)?$`), access: 'public', handler: handleRaw },
    { methods: READ, path: new RegExp(`^/download/${TOKEN}(/[^/]*)?$`), access: 'public', handler: handleDownload },
    { methods: READ, path: new RegExp(`^/thumb/${TOKEN}\\.jpg$`), access: 'public', handler: handleThumb },
    { methods: READ, path: new RegExp(`^/embed/${TOKEN}\\.mp4$`), access: 'public', handler: handleEmbed },
    { methods: READ, path: new RegExp(`^/s/(?<code>${SHORT_PATTERN})$`), access: 'public', handler: handleShortRedirect },
    { methods: ['GET'], path: /^\/api\/links$/, access: 'owner', handler: handleListLinks },
    { methods: ['POST'], path: /^\/api\/links$/, access: 'owner', csrf: true, handler: handleCreateLink },
    { methods: ['DELETE'], path: new RegExp(`^/api/links/(?<code>${SHORT_PATTERN})$`), access: 'owner', csrf: true, handler: handleDeleteLink },
    { methods: ['POST'], path: /^\/logout$/, access: 'owner', csrf: true, handler: handleLogout },
    { methods: ['GET'], path: /^\/api\/files$/, access: 'owner', handler: handleList },
    { methods: ['POST'], path: /^\/api\/upload$/, access: 'owner', csrf: true, handler: handleUpload },
    { methods: ['DELETE'], path: new RegExp(`^/api/files/${TOKEN}$`), access: 'owner', csrf: true, handler: handleDelete },
    // The owner's own sign-in settings. People signed in through OIDC never reach these.
    { methods: ['GET'], path: /^\/api\/passkeys$/, access: 'owner', ownerOnly: true, handler: handlePasskeys },
    { methods: ['POST'], path: /^\/api\/passkeys\/options$/, access: 'owner', ownerOnly: true, csrf: true, handler: handlePasskeyOptions },
    { methods: ['POST'], path: /^\/api\/passkeys$/, access: 'owner', ownerOnly: true, csrf: true, handler: handleAddPasskey },
    { methods: ['DELETE'], path: /^\/api\/passkeys\/(?<id>[A-Za-z0-9_-]{16,1400})$/, access: 'owner', ownerOnly: true, csrf: true, handler: handleRemovePasskey },
    { methods: ['POST'], path: /^\/api\/settings\/codes$/, access: 'owner', ownerOnly: true, csrf: true, handler: handleCodesSetting },
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

    // For the container platform's health check, which can't send the public host name.
    // It reveals nothing beyond the server being up.
    if (req.url === '/healthz' && (req.method === 'GET' || req.method === 'HEAD')) {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' })
      return res.end(req.method === 'HEAD' ? undefined : '{"status":"ok"}')
    }
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
        if (route.ownerOnly && session.member) return refuse(req, res, 403, 'forbidden')
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

  // Expired files are deleted even if nobody asks for them again.
  const sweep = async () => {
    const count = await store.sweep(now())
    if (count) audit('expired', { count })
  }
  const sweeper = setInterval(() => sweep().catch(() => {}), 5 * 60_000).unref()
  server.on('close', () => clearInterval(sweeper))

  return {
    server, store, auth, embeds, routes, sweep,
    init: async () => { await store.init(); await auth.init(); await embeds.init(); await links.init(); await sweep() },
  }
}
