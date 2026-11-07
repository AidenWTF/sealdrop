import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { writeFile, chmod, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileKeys, open, parseToken, seal } from '../src/crypto.js'
import { sniff } from '../src/media.js'
import { allDiskFiles, startApp } from './helpers.js'

const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M/wHwAEBgIApD5fRAAAAABJRU5ErkJggg==', 'base64')
const MP4 = Buffer.concat([Buffer.from([0, 0, 0, 24]), Buffer.from('ftypisom'), Buffer.alloc(1024)])
const meta = (html, key) => new RegExp(`<meta (?:property|name)="${key}" content="([^"]*)"`).exec(html)?.[1]

test('privacy headers are present on every kind of response', async (t) => {
  const ctx = await startApp(t)
  const { pageUrl, rawUrl } = await ctx.upload(await ctx.login(), PNG, 'a.png')
  for (const url of [pageUrl, rawUrl, ctx.base, `${ctx.base}/nope`]) {
    const { headers } = await fetch(url)
    assert.equal(headers.get('referrer-policy'), url === ctx.base ? 'same-origin' : 'no-referrer', url)
    assert.equal(headers.get('x-content-type-options'), 'nosniff', url)
    assert.match(headers.get('x-robots-tag'), /noindex/, url)
    assert.match(headers.get('cache-control'), /no-store/, url)
    assert.ok(headers.get('content-security-policy'), url)
    assert.equal(headers.get('access-control-allow-origin'), null, url)
  }
  const robots = await (await fetch(`${ctx.base}/robots.txt`)).text()
  assert.match(robots, /User-agent: \*\nDisallow: \//)
})

test('HSTS is sent over https', async (t) => {
  const ctx = await startApp(t, { PUBLIC_URL: 'https://files.example.com' })
  const response = await ctx.raw('GET', '/', { Host: 'files.example.com' })
  assert.match(response.headers['strict-transport-security'], /max-age=31536000/)
})

test('active content can never run on this site', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const attacks = [
    ['evil.html', '<!doctype html><script>alert(1)</script>'],
    ['evil.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'],
    ['evil.png', '<script>alert(1)</script>'],
    ['evil.js', 'alert(1)'],
    ['evil.pdf', '%PDF-1.7 evil'],
  ]
  for (const [name, content] of attacks) {
    const file = await ctx.upload(session, content, name)
    assert.equal(file.kind, 'file', name)
    const response = await fetch(file.rawUrl)
    assert.equal(response.headers.get('content-type'), 'application/octet-stream', name)
    assert.match(response.headers.get('content-disposition'), /^attachment/, name)
    assert.match(response.headers.get('content-security-policy'), /sandbox/, name)
  }
})

test('previewable media can play when opened directly, but can never run script', async (t) => {
  const ctx = await startApp(t)
  const { rawUrl } = await ctx.upload(await ctx.login(), MP4, 'clip.mp4')
  const policy = (await fetch(rawUrl)).headers.get('content-security-policy')
  assert.ok(!policy.includes('sandbox'), 'a sandboxed page blocks its own video, because self no longer matches')
  assert.match(policy, /media-src 'self'/)
  assert.match(policy, /default-src 'none'/)
  assert.ok(!policy.includes('script-src'), 'with default-src none, no script may run')
})

test('hostile file names are neutralised', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const xss = '"><script>alert(1)</script><img src=x onerror=alert(1)>.png'
  const file = await ctx.upload(session, PNG, xss)
  const html = await (await fetch(file.pageUrl)).text()
  assert.ok(!html.includes('<script>alert'), 'script must be escaped')
  assert.ok(!html.includes('<img src=x'), 'markup must be escaped')
  assert.ok(html.includes('&lt;script&gt;'))

  const cases = [
    ['../../etc/passwd', '.._.._etc_passwd'],
    ['a\r\nSet-Cookie: pwned=1.txt', 'aSet-Cookie: pwned=1.txt'],
    ['evil‮gnp.exe', 'evilgnp.exe'],
    ['', 'file'],
    ['..', 'file'],
  ]
  for (const [input, expected] of cases) {
    const stored = await ctx.upload(session, 'x', input)
    assert.equal(stored.name, expected)
    const response = await fetch(stored.rawUrl)
    assert.equal(response.headers.get('set-cookie'), null)
    assert.ok(!/[\r\n]/.test(response.headers.get('content-disposition')))
  }
})

test('the Host header cannot poison links in embeds', async (t) => {
  const ctx = await startApp(t)
  const { token } = await ctx.upload(await ctx.login(), PNG, 'a.png')
  const response = await ctx.raw('GET', `/file/${token}`, { Host: 'evil.example' })
  assert.equal(response.status, 421)
  assert.ok(!response.body.includes('evil.example'))
})

test('types come from file contents, not names', () => {
  const cases = [
    [PNG, 'image/png'], [MP4, 'video/mp4'], [Buffer.from('GIF89a'), 'image/gif'],
    [Buffer.from([0xff, 0xd8, 0xff, 0xe0]), 'image/jpeg'],
    [Buffer.concat([Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 1, 2]), Buffer.from('webm')]), 'video/webm'],
    [Buffer.concat([Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 1, 2]), Buffer.from('matroska')]), 'application/octet-stream'],
    [Buffer.from('<!--ftypisom--><MPD>'), 'application/octet-stream'],
    [Buffer.from('<svg></svg>'), 'application/octet-stream'], [Buffer.alloc(0), 'application/octet-stream'],
    [Buffer.concat([Buffer.from([0, 0, 0, 24]), Buffer.from('ftypheic')]), 'application/octet-stream'],
  ]
  for (const [bytes, type] of cases) assert.equal(sniff(bytes).type, type)
})

test('image share page previews and embeds in Discord', async (t) => {
  const ctx = await startApp(t)
  const file = await ctx.upload(await ctx.login(), PNG, 'holiday photo.png')
  const html = await (await fetch(file.pageUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)' } })).text()
  assert.ok(html.includes(`<img class="preview" src="/raw/${file.token}/holiday%20photo.png"`))
  assert.equal(meta(html, 'og:title'), 'holiday photo.png')
  assert.equal(meta(html, 'og:image'), file.rawUrl)
  assert.equal(meta(html, 'og:image:type'), 'image/png')
  assert.equal(meta(html, 'twitter:card'), 'summary_large_image')
  const image = await fetch(meta(html, 'og:image'))
  assert.equal(image.status, 200)
  assert.equal(image.headers.get('content-type'), 'image/png')
  assert.match(image.headers.get('content-disposition'), /^inline/)
})

test('video page has a player and embeds, using probed size and poster', async (t) => {
  // Stand-ins for ffmpeg that really read the decrypted loopback stream, so the wiring is proven.
  const dir = await mkdtemp(join(tmpdir(), 'sealdrop-fake-ffmpeg-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const seen = join(dir, 'seen.bin')
  const probe = join(dir, 'ffprobe')
  const mpeg = join(dir, 'ffmpeg')
  await writeFile(probe, `#!${process.execPath}
(async () => {
  const head = await fetch(process.argv.at(-1), { headers: { Range: 'bytes=4-11' } })
  if (head.status !== 206) process.exit(1)
  require('node:fs').writeFileSync(${JSON.stringify(seen)}, Buffer.from(await head.arrayBuffer()))
  console.log(JSON.stringify({ format: { duration: '12.5' }, streams: [{ codec_type: 'video', codec_name: 'h264', width: 1080, height: 1920, side_data_list: [{ rotation: -90 }] }, { codec_type: 'audio' }] }))
})()
`)
  await writeFile(mpeg, `#!/bin/sh\nprintf 'FAKE-JPEG-BYTES'\n`)
  await chmod(probe, 0o755)
  await chmod(mpeg, 0o755)

  const ctx = await startApp(t, { FFMPEG_PATH: mpeg, FFPROBE_PATH: probe })
  const file = await ctx.upload(await ctx.login(), MP4, 'clip.mp4')
  assert.equal(file.kind, 'video')
  assert.equal((await readFile(seen)).toString('latin1'), 'ftypisom', 'preview tools must see decrypted bytes via range requests')

  const html = await (await fetch(file.pageUrl)).text()
  assert.ok(html.includes('<video class="preview"'))
  assert.equal(meta(html, 'og:type'), 'video.other')
  assert.equal(meta(html, 'og:video'), file.rawUrl)
  assert.equal(meta(html, 'og:video:secure_url'), file.rawUrl)
  assert.equal(meta(html, 'og:video:type'), 'video/mp4')
  assert.equal(meta(html, 'og:video:width'), '1920', 'rotated video swaps dimensions')
  assert.equal(meta(html, 'og:video:height'), '1080')
  assert.equal(meta(html, 'og:image'), `${ctx.base}/thumb/${file.token}.jpg`)

  const thumb = await fetch(meta(html, 'og:image'))
  assert.equal(thumb.headers.get('content-type'), 'image/jpeg')
  assert.equal(await thumb.text(), 'FAKE-JPEG-BYTES')
  for (const { bytes } of await allDiskFiles(ctx.dataDir)) assert.ok(!bytes.includes('FAKE-JPEG-BYTES'), 'thumbnails are encrypted too')
})

test('a file still uploads when ffmpeg is missing', async (t) => {
  const ctx = await startApp(t)
  const file = await ctx.upload(await ctx.login(), MP4, 'clip.mp4')
  const html = await (await fetch(file.pageUrl)).text()
  assert.equal(meta(html, 'og:video:width'), '1280')
  assert.equal(meta(html, 'og:image'), undefined)
})

test('a plain file gets a download card with no preview', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const file = await ctx.upload(session, 'just some bytes', 'project backup.zip')
  const html = await (await fetch(file.pageUrl)).text()
  assert.ok(html.includes('class="card file-card"'))
  assert.ok(html.includes('<div class="file-icon" aria-hidden="true">ZIP</div>'))
  assert.ok(html.includes('<h1>project backup.zip</h1>'))
  assert.ok(html.includes(`href="/download/${file.token}/project%20backup.zip"`))
  assert.ok(!/<(img|video|audio)\b/.test(html))

  const noExtension = await (await fetch((await ctx.upload(session, 'x', 'README')).pageUrl)).text()
  assert.ok(noExtension.includes('>FILE</div>'))
  const hostile = await (await fetch((await ctx.upload(session, 'x', 'a.<b>x')).pageUrl)).text()
  assert.ok(hostile.includes('>FILE</div>'), 'an unusual extension falls back to the generic label')
  assert.ok(!hostile.includes('<b>x'))
})

test('download pages show the correct MD5 and upload date', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  ctx.clock.ms = Date.UTC(2026, 10, 3, 15, 6, 40)

  // Sizes either side of the 1 MiB encryption chunk, plus an empty file.
  for (const size of [0, 1, 1024 * 1024, 1024 * 1024 + 1, 3 * 1024 * 1024 + 17]) {
    const content = randomBytes(size)
    const html = await (await fetch((await ctx.upload(session, content, 'data.bin')).pageUrl)).text()
    assert.ok(html.includes(`<code>${createHash('md5').update(content).digest('hex')}</code>`), `size ${size}`)
  }
  for (const [body, name] of [[PNG, 'a.png'], [MP4, 'b.mp4'], ['plain', 'c.zip']]) {
    const html = await (await fetch((await ctx.upload(session, body, name)).pageUrl)).text()
    assert.ok(html.includes(`<code>${createHash('md5').update(body).digest('hex')}</code>`), name)
    assert.ok(html.includes('<time datetime="2026-11-03T15:06:40.000Z">Nov 3, 2026, 15:06 UTC</time>'), name)
  }
})

test('midnight is shown as 00:00, not 24:00', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  ctx.clock.ms = Date.UTC(2026, 10, 3, 0, 5)
  const html = await (await fetch((await ctx.upload(session, 'x')).pageUrl)).text()
  assert.ok(html.includes('Nov 3, 2026, 00:05 UTC'))
})

test('a file stored before MD5 existed still opens, just without one', async (t) => {
  const ctx = await startApp(t)
  const { token, pageUrl } = await ctx.upload(await ctx.login(), 'older file')
  const keys = fileKeys(parseToken(token))
  const path = join(ctx.dataDir, 'files', keys.id, 'meta')
  const { md5, ...older } = JSON.parse(open(keys.meta, await readFile(path)).toString('utf8'))
  assert.ok(md5)
  await writeFile(path, seal(keys.meta, JSON.stringify(older)))
  const response = await fetch(pageUrl)
  assert.equal(response.status, 200)
  const html = await response.text()
  assert.ok(!html.includes('MD5'))
  assert.ok(html.includes('Uploaded'))
})

test('share links are short and readable', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const cases = [
    ['project backup.zip', 'project-backup.zip'], ['demo clip.mp4', 'demo-clip.mp4'],
    ['résumé.pdf', 'resume.pdf'], ['报告.pdf', 'file.pdf'], ['README', 'README'], ['???', 'file'],
    ['report (final).tar.gz', 'report-final.tar.gz'], ['<script>.txt', 'script.txt'],
    [`${'x'.repeat(150)}.mp4`, `${'x'.repeat(60)}.mp4`],
  ]
  for (const [name, expected] of cases) {
    const { pageUrl, token } = await ctx.upload(session, 'x', name)
    assert.equal(pageUrl, `${ctx.base}/file/${token}/${expected}`, name)
    assert.match(token, /^[1-9A-HJ-NP-Za-km-z]{22}$/)
    assert.equal((await fetch(pageUrl)).status, 200, name)
  }
})

test('only the secret in a share link matters, not the name after it', async (t) => {
  const ctx = await startApp(t)
  const { token, pageUrl } = await ctx.upload(await ctx.login(), 'x', 'real-name.txt')
  const page = await (await fetch(pageUrl)).text()
  for (const path of [`/file/${token}`, `/file/${token}/`, `/file/${token}/some-other-name.exe`]) {
    const response = await fetch(ctx.base + path)
    assert.equal(response.status, 200, path)
    assert.equal(await response.text(), page, 'the page always shows the real name')
  }
  assert.equal((await ctx.raw('GET', `/file/${token}/a/b`)).status, 404)
})

test('robots.txt lets Discord reach embeds but keeps other crawlers out', async (t) => {
  const ctx = await startApp(t)
  const robots = await (await fetch(`${ctx.base}/robots.txt`)).text()
  for (const path of ['/file/', '/raw/', '/thumb/']) assert.ok(robots.includes(`Allow: ${path}`), path)
  assert.match(robots, /User-agent: \*\nDisallow: \//)
})

test('a forced download is an attachment', async (t) => {
  const ctx = await startApp(t)
  const { token, rawUrl } = await ctx.upload(await ctx.login(), PNG, 'a.png')
  const response = await fetch(`${ctx.base}/download/${token}/a.png`)
  assert.match(response.headers.get('content-disposition'), /^attachment; filename="a\.png"/)
  assert.ok(Buffer.from(await response.arrayBuffer()).equals(PNG))
  assert.match((await fetch(rawUrl)).headers.get('content-disposition'), /^inline/)
})
