import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { test } from 'node:test'
import { MetadataError, cleanJpeg, exifOrientation } from '../src/jpegclean.js'
import { startApp } from './helpers.js'

const segment = (marker, payload) => {
  const head = Buffer.from([0xff, marker, 0, 0])
  head.writeUInt16BE(payload.length + 2, 2)
  return Buffer.concat([head, payload])
}

// EXIF with an orientation and a camera string standing in for the location data.
function exif(orientation, little = false) {
  const make = Buffer.from('SecretCam GPS 51.5007N 0.1246W\0')
  const tiff = Buffer.alloc(8 + 2 + 2 * 12 + 4)
  const u16 = (v, at) => (little ? tiff.writeUInt16LE(v, at) : tiff.writeUInt16BE(v, at))
  const u32 = (v, at) => (little ? tiff.writeUInt32LE(v, at) : tiff.writeUInt32BE(v, at))
  tiff.write(little ? 'II' : 'MM', 0, 'latin1')
  u16(42, 2)
  u32(8, 4)
  u16(2, 8)
  u16(0x010f, 10); u16(2, 12); u32(make.length, 14); u32(tiff.length, 18) // Make, stored after the IFD
  u16(0x0112, 22); u16(3, 24); u32(1, 26); u16(orientation, 30) // Orientation
  u32(0, 34)
  return Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff, make])
}

function dirtyJpeg(clean, { orientation = 6, little = false } = {}) {
  assert.deepEqual([...clean.subarray(0, 2)], [0xff, 0xd8])
  const extras = [
    segment(0xe1, exif(orientation, little)),
    segment(0xe1, Buffer.from('http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>GPSLatitude secret</x:xmpmeta>')),
    segment(0xfe, Buffer.from('comment: shot at home, secret')),
    segment(0xed, Buffer.from('Photoshop 3.0\0 IPTC secret city')),
    segment(0xe2, Buffer.from('MPF\0 index to a secret second image')),
    segment(0xe2, Buffer.from('ICC_PROFILE\0\x01\x01 colours to keep')),
  ]
  const trailer = Buffer.from('....ftypmp42 motion photo video with secret location....')
  return Buffer.concat([clean.subarray(0, 2), ...extras, clean.subarray(2), trailer])
}

async function run(chunks) {
  return Buffer.concat(await Array.fromAsync(cleanJpeg((async function* () { yield* chunks })())))
}

let base
try {
  base = execFileSync('ffmpeg', ['-v', 'error', '-f', 'lavfi', '-i', 'testsrc=size=64x48', '-frames:v', '1', '-f', 'mjpeg', '-'])
} catch {
  base = null
}
const skip = !base && 'ffmpeg not available'

test('location, camera details and trailing extras are removed; orientation and colours stay', { skip }, async () => {
  const dirty = dirtyJpeg(base)
  const cleaned = await run([dirty])
  assert.ok(!cleaned.includes('secret'), 'nothing personal survives')
  assert.ok(!cleaned.includes('SecretCam'))
  assert.ok(!cleaned.includes('MPF\0'))
  assert.ok(cleaned.includes('ICC_PROFILE'), 'the colour profile stays')
  assert.deepEqual([...cleaned.subarray(-2)], [0xff, 0xd9], 'it ends where the picture ends')
  const app1 = cleaned.indexOf(Buffer.from([0xff, 0xe1]))
  assert.equal(exifOrientation(cleaned.subarray(app1 + 4, app1 + 4 + cleaned.readUInt16BE(app1 + 2) - 2)), 6)
  const probed = JSON.parse(execFileSync('ffprobe', ['-v', 'error', '-print_format', 'json', '-show_streams', '-'], { input: cleaned }))
  assert.equal(probed.streams[0].width, 64, 'still a working picture')
})

test('the result is the same however the upload is split into pieces', { skip }, async () => {
  const dirty = dirtyJpeg(base, { little: true })
  const whole = await run([dirty])
  const bytes = []
  for (let i = 0; i < dirty.length; i++) bytes.push(dirty.subarray(i, i + 1))
  assert.ok((await run(bytes)).equals(whole))
  const odd = []
  for (let i = 0; i < dirty.length; i += 7) odd.push(dirty.subarray(i, i + 7))
  assert.ok((await run(odd)).equals(whole))
  const app1 = whole.indexOf(Buffer.from([0xff, 0xe1]))
  assert.equal(exifOrientation(whole.subarray(app1 + 4)), 6, 'little-endian EXIF is read too')
})

test('a photo without orientation gets no EXIF at all, and other files pass untouched', { skip }, async () => {
  const cleaned = await run([dirtyJpeg(base, { orientation: 0 })])
  assert.equal(cleaned.indexOf(Buffer.from([0xff, 0xe1])), -1)
  const other = Buffer.from('%PDF-1.7 not a photo, with GPS data inside')
  assert.ok((await run([other.subarray(0, 5), other.subarray(5)])).equals(other))
})

test('a broken photo header is refused rather than stored with its metadata', async () => {
  const truncated = Buffer.concat([Buffer.from([0xff, 0xd8]), segment(0xe1, exif(1)).subarray(0, 20)])
  await assert.rejects(run([truncated]), MetadataError)
  await assert.rejects(run([Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x01])]), MetadataError)
})

test('uploads are cleaned unless the owner keeps metadata', { skip }, async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const dirty = dirtyJpeg(base)
  const send = (headers) => fetch(`${ctx.base}/api/upload`, {
    method: 'POST', headers: { ...session.ownerHeaders, 'X-File-Name': 'photo.jpg', ...headers }, body: dirty,
  }).then((r) => r.json())

  const cleaned = await send({})
  const stored = Buffer.from(await (await fetch(cleaned.rawUrl)).arrayBuffer())
  assert.ok(!stored.includes('secret'))
  assert.equal(cleaned.size, stored.length, 'size and MD5 describe the stored photo')

  const kept = await send({ 'X-Keep-Metadata': '1' })
  assert.ok(Buffer.from(await (await fetch(kept.rawUrl)).arrayBuffer()).equals(dirty))

  const broken = await fetch(`${ctx.base}/api/upload`, {
    method: 'POST',
    headers: { ...session.ownerHeaders, 'X-File-Name': 'bad.jpg' },
    body: Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x01]),
  })
  assert.equal(broken.status, 422)
})
