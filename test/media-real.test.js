// Runs the real ffmpeg over real media. Skipped when ffmpeg isn't available, for example:
//   FFMPEG_PATH=/path/to/ffmpeg FFPROBE_PATH=/path/to/ffprobe npm test
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { allDiskFiles, startApp } from './helpers.js'

const ffmpeg = process.env.FFMPEG_PATH ?? 'ffmpeg'
const ffprobe = process.env.FFPROBE_PATH ?? 'ffprobe'
let available = true
try {
  execFileSync(ffmpeg, ['-version'], { stdio: 'ignore' })
  execFileSync(ffprobe, ['-version'], { stdio: 'ignore' })
} catch {
  available = false
}
const meta = (html, key) => new RegExp(`<meta (?:property|name)="${key}" content="([^"]*)"`).exec(html)?.[1]
const VIDEO_SOURCE = ['-f', 'lavfi', '-i', 'testsrc=size=640x360:rate=24:duration=3', '-f', 'lavfi', '-i', 'sine=frequency=440:duration=3']

const SAMPLES = [
  { name: 'index-at-end.mp4', kind: 'video', type: 'video/mp4', width: 640, height: 360, args: [...VIDEO_SOURCE, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-shortest'] },
  { name: 'faststart.mp4', kind: 'video', type: 'video/mp4', width: 640, height: 360, args: [...VIDEO_SOURCE, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-shortest', '-movflags', '+faststart'] },
  { name: 'portrait-phone.mp4', kind: 'video', type: 'video/mp4', width: 360, height: 640, prefix: ['-display_rotation', '90'], remux: true },
  { name: 'clip.webm', kind: 'video', type: 'video/webm', width: 640, height: 360, args: ['-f', 'lavfi', '-i', 'testsrc=size=640x360:rate=12:duration=1', '-c:v', 'libvpx', '-b:v', '200k'] },
  { name: 'picture.png', kind: 'image', type: 'image/png', width: 1600, height: 900, args: ['-f', 'lavfi', '-i', 'testsrc=size=1600x900', '-frames:v', '1'] },
  { name: 'picture.jpg', kind: 'image', type: 'image/jpeg', width: 320, height: 240, args: ['-f', 'lavfi', '-i', 'testsrc=size=320x240', '-frames:v', '1'] },
  { name: 'moving.gif', kind: 'image', type: 'image/gif', width: 160, height: 120, args: ['-f', 'lavfi', '-i', 'testsrc=size=160x120:rate=5:duration=1'] },
  { name: 'picture.webp', kind: 'image', type: 'image/webp', width: 320, height: 240, args: ['-f', 'lavfi', '-i', 'testsrc=size=320x240', '-frames:v', '1'], optional: true },
  { name: 'picture.avif', kind: 'image', type: 'image/avif', width: 320, height: 240, args: ['-f', 'lavfi', '-i', 'testsrc=size=320x240', '-frames:v', '1', '-c:v', 'libaom-av1', '-still-picture', '1', '-pix_fmt', 'yuv420p'], optional: true },
  { name: 'sound.mp3', kind: 'audio', type: 'audio/mpeg', args: ['-f', 'lavfi', '-i', 'sine=frequency=440:duration=1'], optional: true },
  { name: 'only-sound.m4a', kind: 'audio', type: 'audio/mp4', args: ['-f', 'lavfi', '-i', 'sine=frequency=440:duration=1', '-c:a', 'aac'] },
]

function make(dir, sample) {
  const out = join(dir, sample.name)
  if (sample.remux) {
    const source = join(dir, 'rotation-source.mp4')
    execFileSync(ffmpeg, ['-y', '-v', 'error', ...VIDEO_SOURCE, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-shortest', source])
    execFileSync(ffmpeg, ['-y', '-v', 'error', ...sample.prefix, '-i', source, '-c', 'copy', out])
  } else {
    execFileSync(ffmpeg, ['-y', '-v', 'error', ...sample.args, out])
  }
  return readFile(out)
}

test('real media gets correct types, sizes and thumbnails, with nothing readable on disk', { skip: !available && 'ffmpeg not available' }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'sealdrop-media-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const ctx = await startApp(t, { FFMPEG_PATH: ffmpeg, FFPROBE_PATH: ffprobe })
  const session = await ctx.login()

  for (const sample of SAMPLES) {
    let bytes
    try {
      bytes = await make(dir, sample)
    } catch (err) {
      if (sample.optional) continue // this ffmpeg build may lack the encoder
      throw err
    }
    await t.test(sample.name, async () => {
      const file = await ctx.upload(session, bytes, sample.name)
      assert.equal(file.kind, sample.kind)

      const raw = await fetch(file.rawUrl)
      assert.equal(raw.headers.get('content-type'), sample.type)
      assert.ok(Buffer.from(await raw.arrayBuffer()).equals(bytes), 'the file comes back byte-exact')

      const html = await (await fetch(file.pageUrl)).text()
      if (sample.kind === 'audio') {
        assert.equal(file.thumbUrl, null)
        assert.equal(meta(html, 'og:audio'), file.rawUrl)
        return
      }
      const prefix = sample.kind === 'video' ? 'og:video' : 'og:image'
      assert.equal(meta(html, `${prefix}:width`), String(sample.width))
      assert.equal(meta(html, `${prefix}:height`), String(sample.height))

      const thumb = Buffer.from(await (await fetch(ctx.base + file.thumbUrl)).arrayBuffer())
      assert.deepEqual([...thumb.subarray(0, 3)], [0xff, 0xd8, 0xff], 'the thumbnail is a real JPEG')
      assert.ok(thumb.length > 500, 'the thumbnail has real content')
      const probed = JSON.parse(execFileSync(ffprobe, ['-v', 'error', '-print_format', 'json', '-show_streams', '-f', 'mjpeg', '-'], { input: thumb }))
      assert.ok(probed.streams[0].width <= 960, 'the thumbnail is scaled down')

      for (const { bytes: stored, path } of await allDiskFiles(ctx.dataDir)) {
        assert.ok(!stored.includes(thumb.subarray(0, 64)), `thumbnail readable in ${path}`)
        assert.ok(!stored.includes(bytes.subarray(0, Math.min(64, bytes.length))), `upload readable in ${path}`)
      }
    })
  }
})

test('a crafted upload cannot make ffmpeg fetch other addresses', { skip: !available && 'ffmpeg not available' }, async (t) => {
  // A file that passes as MP4 by its first bytes but that ffmpeg would read as a DASH manifest.
  const hits = []
  const canary = createServer((req, res) => {
    hits.push(req.url)
    res.writeHead(404).end()
  })
  await new Promise((resolve) => canary.listen(0, '127.0.0.1', resolve))
  t.after(() => canary.close())
  const target = `http://127.0.0.1:${canary.address().port}/`
  const manifest = (prefix) => `${prefix}<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static" mediaPresentationDuration="PT2S" minBufferTime="PT1S" profiles="urn:mpeg:dash:profile:isoff-on-demand:2011"><Period><AdaptationSet mimeType="video/mp4" contentType="video"><Representation id="1" bandwidth="1000" width="16" height="16" codecs="avc1.42c00a"><BaseURL>${target}leak.mp4</BaseURL><SegmentBase indexRange="0-1"><Initialization range="0-1"/></SegmentBase></Representation></AdaptationSet></Period></MPD>`

  const ctx = await startApp(t, { FFMPEG_PATH: ffmpeg, FFPROBE_PATH: ffprobe })
  const session = await ctx.login()
  for (const prefix of ['<!--ftypjp2 -->', '<!--ftypjP  -->', '<!--ftypisom-->', '<!--ftypmp42-->']) {
    await ctx.upload(session, manifest(prefix), 'funny.mp4')
  }
  // And the same manifest behind a well-formed ftyp box, which must also go nowhere.
  const box = Buffer.concat([Buffer.from([0, 0, 0, 16]), Buffer.from('ftypjp2 \0\0\0\0'), Buffer.from(manifest(''))])
  await ctx.upload(session, box, 'funny2.mp4')
  assert.deepEqual(hits, [])
})
