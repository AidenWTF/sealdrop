// Discord-sized copies of large videos. The end-to-end tests run the real ffmpeg and are
// skipped without it, like media-real.test.js.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { RAM_DIR } from '../src/embeds.js'
import { EMBED_TARGET_BYTES, embedPlan } from '../src/media.js'
import { allDiskFiles, startApp } from './helpers.js'

const ffmpeg = process.env.FFMPEG_PATH ?? 'ffmpeg'
const ffprobe = process.env.FFPROBE_PATH ?? 'ffprobe'
let available = existsSync(RAM_DIR)
try {
  execFileSync(ffmpeg, ['-version'], { stdio: 'ignore' })
  execFileSync(ffprobe, ['-version'], { stdio: 'ignore' })
} catch {
  available = false
}
const skip = !available && 'ffmpeg or /dev/shm not available'
const FFMPEG_ENV = { FFMPEG_PATH: ffmpeg, FFPROBE_PATH: ffprobe }
const meta = (html, key) => new RegExp(`<meta (?:property|name)="${key}" content="([^"]*)"`).exec(html)?.[1]

async function waitFor(check, what) {
  const deadline = Date.now() + 120_000
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
}

const countEvents = (ctx, name) => ctx.events.filter((e) => e.event === name).length

async function makeVideo(t, size = '1280x720') {
  const dir = await mkdtemp(join(tmpdir(), 'sealdrop-embed-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const out = join(dir, 'clip.mp4')
  execFileSync(ffmpeg, ['-y', '-v', 'error',
    '-f', 'lavfi', '-i', `testsrc=size=${size}:rate=24:duration=3`, '-f', 'lavfi', '-i', 'sine=frequency=440:duration=3',
    '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-shortest', out])
  return readFile(out)
}

test('the copy plan fits the target, lowers resolution for long videos, and gives up when too long', () => {
  const short = embedPlan(2 * 60)
  assert.equal(short.height, 1080)
  const medium = embedPlan(4 * 60)
  assert.equal(medium.height, 720)
  const long = embedPlan(10 * 60)
  assert.equal(long.height, 480)
  for (const [seconds, plan] of [[120, short], [240, medium], [600, long]]) {
    const bytes = ((plan.videoBps + 96_000) * seconds) / 8
    assert.ok(bytes < EMBED_TARGET_BYTES, `${seconds}s fits the target`)
  }
  assert.equal(embedPlan(20 * 60).skip, 'too long')
  assert.equal(embedPlan(undefined).skip, 'unknown length')
  assert.equal(embedPlan(1).videoBps, 8_000_000, 'very short videos are capped, not given absurd bitrates')
})

test('a large video gets an encrypted, faststart H.264 copy that only the embed tags use', { skip }, async (t) => {
  const ctx = await startApp(t, { ...FFMPEG_ENV, DISCORD_COPY_OVER_MB: '0' })
  const session = await ctx.login()
  const original = await makeVideo(t)
  const file = await ctx.upload(session, original, 'big video.mp4')
  await waitFor(() => countEvents(ctx, 'embed_ok') === 1, 'the copy')
  await ctx.app.embeds.idle()

  const html = await (await fetch(file.pageUrl)).text()
  const embedUrl = `${ctx.base}/embed/${file.token}.mp4`
  assert.equal(meta(html, 'og:video'), embedUrl)
  assert.equal(meta(html, 'og:video:secure_url'), embedUrl)
  assert.equal(meta(html, 'og:video:type'), 'video/mp4')
  assert.equal(meta(html, 'og:video:width'), '1280')
  assert.equal(meta(html, 'og:video:height'), '720')
  assert.match(html, new RegExp(`<video class="preview" src="/raw/${file.token}/`), 'the page itself plays the original')

  const response = await fetch(embedUrl)
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('content-type'), 'video/mp4')
  const copy = Buffer.from(await response.arrayBuffer())
  assert.ok(copy.indexOf('moov') < copy.indexOf('mdat'), 'the index is at the front')
  const probed = JSON.parse(execFileSync(ffprobe, ['-v', 'error', '-print_format', 'json', '-show_streams', '-'], { input: copy }))
  assert.deepEqual(probed.streams.map((s) => s.codec_name).sort(), ['aac', 'h264'])

  const range = await fetch(embedUrl, { headers: { Range: 'bytes=0-99' } })
  assert.equal(range.status, 206)
  assert.equal((await range.arrayBuffer()).byteLength, 100)

  const raw = Buffer.from(await (await fetch(file.rawUrl)).arrayBuffer())
  assert.ok(raw.equals(original), 'the original is untouched')

  for (const { bytes, path } of await allDiskFiles(ctx.dataDir)) {
    assert.ok(!bytes.includes(copy.subarray(copy.length - 4096, copy.length - 4032)), `copy readable in ${path}`)
  }
  assert.deepEqual((await readdir(RAM_DIR)).filter((name) => name.startsWith('sealdrop-')), [], 'nothing is left in memory')

  const removed = await fetch(`${ctx.base}/api/files/${file.token}`, { method: 'DELETE', headers: session.ownerHeaders })
  assert.equal(removed.status, 200)
  assert.equal((await fetch(embedUrl)).status, 404)
})

test('videos under the size limit get no copy and embed the original', { skip }, async (t) => {
  const ctx = await startApp(t, FFMPEG_ENV)
  const session = await ctx.login()
  const file = await ctx.upload(session, await makeVideo(t), 'small.mp4')
  await ctx.app.embeds.idle()
  const html = await (await fetch(file.pageUrl)).text()
  assert.equal(meta(html, 'og:video'), file.rawUrl)
  assert.equal((await fetch(`${ctx.base}/embed/${file.token}.mp4`)).status, 404)
  assert.equal(countEvents(ctx, 'embed_ok') + countEvents(ctx, 'embed_skipped'), 0)
})

test('videos uploaded before copies existed get one when the dashboard lists them', { skip }, async (t) => {
  const before = await startApp(t, { ...FFMPEG_ENV, DISCORD_COPIES: '0' })
  const file = await before.upload(await before.login(), await makeVideo(t, '640x360'), 'old.mp4')
  await before.app.embeds.idle()
  assert.equal(countEvents(before, 'embed_ok'), 0)

  const after = await startApp(t, { ...FFMPEG_ENV, DISCORD_COPY_OVER_MB: '0' }, { dataDir: before.dataDir, secrets: before.secrets })
  after.clock.ms = before.clock.ms + 60_000 // each authenticator code works once, across restarts too
  const session = await after.login()
  assert.equal((await fetch(`${after.base}/api/files`, { headers: session.ownerHeaders })).status, 200)
  await waitFor(() => countEvents(after, 'embed_ok') === 1, 'the copy')
  await after.app.embeds.idle()
  const html = await (await fetch(`${after.base}/file/${file.token}/old.mp4`)).text()
  assert.equal(meta(html, 'og:video'), `${after.base}/embed/${file.token}.mp4`)
})

test('a video that cannot be copied is recorded once and not retried', { skip }, async (t) => {
  const ctx = await startApp(t, { ...FFMPEG_ENV, DISCORD_COPY_OVER_MB: '0' })
  const session = await ctx.login()
  const broken = Buffer.concat([Buffer.from([0, 0, 0, 16]), Buffer.from('ftypisom\0\0\0\0'), Buffer.alloc(4096, 7)])
  const file = await ctx.upload(session, broken, 'broken.mp4')
  await waitFor(() => countEvents(ctx, 'embed_skipped') === 1, 'the skip')
  await ctx.app.embeds.idle()
  for (let i = 0; i < 2; i++) await fetch(`${ctx.base}/api/files`, { headers: session.ownerHeaders })
  await ctx.app.embeds.idle()
  assert.equal(countEvents(ctx, 'embed_skipped'), 1)
  const html = await (await fetch(file.pageUrl)).text()
  assert.equal(meta(html, 'og:video'), file.rawUrl)
})
