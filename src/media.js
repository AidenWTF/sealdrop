// File type detection and previews. The type comes from the file's own bytes, never from
// the browser or the file name. Anything not on this allowlist is served as a download,
// which is what stops an uploaded HTML or SVG file from running script on this site.
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { stat } from 'node:fs/promises'
import { createServer } from 'node:http'
import { setPriority } from 'node:os'
import { sendBytes } from './http.js'

const FALLBACK = { type: 'application/octet-stream', kind: 'file' }

export function sniff(head) {
  const ascii = (start, end) => head.toString('latin1', start, end)
  if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return { type: 'image/jpeg', kind: 'image' }
  if (head.length >= 8 && head.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { type: 'image/png', kind: 'image' }
  if (ascii(0, 4) === 'GIF8') return { type: 'image/gif', kind: 'image' }
  if (ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WEBP') return { type: 'image/webp', kind: 'image' }
  if (ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WAVE') return { type: 'audio/wav', kind: 'audio' }
  // A real ftyp box is small, so its 32-bit length starts with zeros. Without this check,
  // text that merely has "ftyp" at offset 4 would be treated as a video and handed to ffmpeg.
  if (ascii(4, 8) === 'ftyp' && head[0] === 0 && head[1] === 0) {
    const brand = ascii(8, 12)
    if (brand === 'avif' || brand === 'avis') return { type: 'image/avif', kind: 'image' }
    if (['heic', 'heix', 'heim', 'heis', 'hevc', 'hevx', 'mif1', 'msf1'].includes(brand)) return FALLBACK
    if (brand === 'M4A ' || brand === 'M4B ') return { type: 'audio/mp4', kind: 'audio' }
    return { type: 'video/mp4', kind: 'video' }
  }
  if (head.length >= 4 && head.readUInt32BE(0) === 0x1a45dfa3) {
    return head.includes('webm', 0, 'latin1') ? { type: 'video/webm', kind: 'video' } : FALLBACK
  }
  if (ascii(0, 4) === 'OggS') return { type: 'audio/ogg', kind: 'audio' }
  if (ascii(0, 4) === 'fLaC') return { type: 'audio/flac', kind: 'audio' }
  if (ascii(0, 3) === 'ID3' || (head.length >= 2 && head[0] === 0xff && (head[1] & 0xe0) === 0xe0)) return { type: 'audio/mpeg', kind: 'audio' }
  if (looksLikeText(head)) return { type: 'text/plain; charset=utf-8', kind: 'text' }
  return FALLBACK
}

// UTF-8 (or ASCII) with no control characters other than layout ones. Text files are
// previewed as escaped text on the share page and still download as files, so HTML,
// SVG and scripts land here safely: they are shown, never run.
function looksLikeText(head) {
  if (head.length === 0) return false
  for (const byte of head) {
    if (byte < 0x20 && ![0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b].includes(byte)) return false
    if (byte === 0x7f) return false
  }
  try {
    // A full sample may end partway through a character, which isn't an error. A shorter
    // sample is the whole file, so it must end on a complete character.
    new TextDecoder('utf-8', { fatal: true }).decode(head, { stream: head.length >= 4096 })
    return true
  } catch {
    return false
  }
}

// `background` runs the program at the lowest CPU priority, so long encodes don't slow the site.
function run(bin, args, { timeoutMs = 90_000, background = false } = {}) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'ignore'] })
    if (background && child.pid) {
      try {
        setPriority(child.pid, 19)
      } catch {}
    }
    const kill = () => child.kill('SIGKILL')
    process.once('exit', kill)
    const timer = setTimeout(kill, timeoutMs)
    const finish = (value) => {
      clearTimeout(timer)
      process.off('exit', kill)
      resolve(value)
    }
    const out = []
    let total = 0
    child.stdout.on('data', (piece) => {
      total += piece.length
      if (total > 32 * 1024 * 1024) child.kill('SIGKILL')
      else out.push(piece)
    })
    child.on('error', () => finish(null))
    child.on('close', (code) => finish(code === 0 ? Buffer.concat(out) : null))
  })
}

// ffmpeg reads the upload through a one-shot loopback server that decrypts on demand, so
// previews can be built, even for files whose index sits at the end, without plaintext on disk.
async function withLoopback(read, size, work) {
  const path = `/${randomBytes(32).toString('hex')}`
  const server = createServer((req, res) => {
    if (req.url !== path) {
      res.writeHead(404).end()
      return
    }
    sendBytes(req, res, { size, read, headers: { 'Content-Type': 'application/octet-stream' } }).catch(() => res.destroy())
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    return await work(`http://127.0.0.1:${server.address().port}${path}`)
  } finally {
    server.closeAllConnections()
    server.close()
  }
}

// ffmpeg picks a format from file contents, not from what sniff() decided. The format list
// stops a crafted upload being read as a playlist or manifest (DASH, HLS, concat...), which
// would make ffmpeg fetch addresses named inside the file.
const INPUT_ARGS = [
  '-protocol_whitelist', 'http,tcp',
  '-format_whitelist', 'mov,mp4,m4a,3gp,3g2,mj2,matroska,webm,gif,png_pipe,jpeg_pipe,webp_pipe,mp3,wav,ogg,flac',
]

function probeInfo(json) {
  let parsed
  try {
    parsed = JSON.parse(json.toString('utf8'))
  } catch {
    return {}
  }
  const streams = parsed.streams ?? []
  const video = streams.find((s) => s.codec_type === 'video')
  const duration = Number(parsed.format?.duration)
  const info = { hasAudio: streams.some((s) => s.codec_type === 'audio'), hasVideo: Boolean(video) }
  if (Number.isFinite(duration)) info.duration = duration
  if (video) {
    info.codec = video.codec_name
    info.width = video.width
    info.height = video.height
    const rotation = Math.abs(Number(video.side_data_list?.find((d) => d.rotation !== undefined)?.rotation ?? video.tags?.rotate ?? 0))
    if (rotation === 90 || rotation === 270) [info.width, info.height] = [info.height, info.width]
  }
  return info
}

const grabFrame = (config, url, seek) => run(config.ffmpegPath, [
  '-nostdin', '-v', 'error', ...INPUT_ARGS, ...(seek ? ['-ss', String(seek)] : []), '-i', url,
  '-map_metadata', '-1', '-frames:v', '1', '-vf', "scale='min(960,iw)':-2:flags=lanczos,format=yuvj420p",
  '-c:v', 'mjpeg', '-q:v', '4', '-f', 'image2pipe', 'pipe:1',
])

// Colours of the site's dark theme, so sound files get a picture that matches it.
const WAVE_COLOR = '0x7482ff'
const WAVE_BACKGROUND = '0x191c24'

// A picture of the whole sound's waveform, for files without cover art.
const waveformPicture = (config, url) => run(config.ffmpegPath, [
  '-nostdin', '-v', 'error', ...INPUT_ARGS, '-i', url, '-map_metadata', '-1',
  '-filter_complex', `[0:a:0]aformat=channel_layouts=mono,showwavespic=s=960x540:colors=${WAVE_COLOR}:scale=sqrt[w];color=c=${WAVE_BACKGROUND}:s=960x540[bg];[bg][w]overlay=format=auto,format=yuvj420p`,
  '-frames:v', '1', '-c:v', 'mjpeg', '-q:v', '4', '-f', 'image2pipe', 'pipe:1',
])

const probe = async (config, url) => {
  const probed = await run(config.ffprobePath, [
    '-v', 'error', ...INPUT_ARGS, '-print_format', 'json', '-show_format', '-show_streams', url,
  ])
  return probed ? probeInfo(probed) : null
}

// Best effort: a file that can't be analysed still uploads, just without a thumbnail.
export async function analyze(sniffed, read, size, config) {
  if (!['image', 'video', 'audio'].includes(sniffed.kind) || size === 0) return { ...sniffed, thumb: null }
  return withLoopback(read, size, async (url) => {
    const info = await probe(config, url)
    // An MP4 container holding only sound is audio.
    const audioOnlyMp4 = sniffed.kind === 'video' && info && !info.hasVideo && info.hasAudio
    if (sniffed.kind === 'audio' || audioOnlyMp4) {
      const result = audioOnlyMp4 ? { ...sniffed, type: 'audio/mp4', kind: 'audio' } : { ...sniffed }
      if (info?.duration) result.duration = info.duration
      // Cover art shows up as a video stream. Without it, a waveform stands in.
      let thumb = info?.hasVideo ? await grabFrame(config, url, 0) : null
      if (!thumb?.length) thumb = await waveformPicture(config, url)
      return { ...result, thumb: thumb?.length ? thumb : null }
    }
    const result = { ...sniffed }
    if (info?.width && info?.height) Object.assign(result, { width: info.width, height: info.height })
    if (sniffed.kind === 'video') {
      if (info?.duration) result.duration = info.duration
      if (info?.codec) result.codec = info.codec
    }
    const seek = sniffed.kind === 'video' ? Math.min(1, (info?.duration ?? 0) / 2) : 0
    let thumb = await grabFrame(config, url, seek)
    if (seek && !thumb?.length) thumb = await grabFrame(config, url, 0)
    return { ...result, thumb: thumb?.length ? thumb : null }
  })
}

export async function ffmpegAvailable(config) {
  const [probe, mpeg] = await Promise.all([
    run(config.ffprobePath, ['-version'], { timeoutMs: 10_000 }),
    run(config.ffmpegPath, ['-version'], { timeoutMs: 10_000 }),
  ])
  return Boolean(probe && mpeg)
}

// Discord won't embed a video it can't fetch within its own limits, which a large file
// exceeds (its fetches stop at 50 MB). Large videos therefore get a smaller H.264 copy that
// is used only for the embed. The copy aims well under the limit, and is dropped if over.
export const EMBED_TARGET_BYTES = 40 * 1024 * 1024
export const EMBED_MAX_BYTES = 45 * 1024 * 1024
const EMBED_AUDIO_BPS = 96_000
const EMBED_MIN_VIDEO_BPS = 300_000
const EMBED_MAX_VIDEO_BPS = 8_000_000

// The video bitrate that fits the target for this length, and a height that suits it.
// Below the minimum the picture would be too poor to be worth showing (about 13 minutes).
export function embedPlan(duration) {
  if (!(duration > 0)) return { skip: 'unknown length' }
  const fit = Math.floor((EMBED_TARGET_BYTES * 8 * 0.92) / duration) - EMBED_AUDIO_BPS
  if (fit < EMBED_MIN_VIDEO_BPS) return { skip: 'too long' }
  const videoBps = Math.min(fit, EMBED_MAX_VIDEO_BPS)
  const height = videoBps >= 2_000_000 ? 1080 : videoBps >= 1_000_000 ? 720 : 480
  return { videoBps, height }
}

// Sound files: Discord has no audio player for links, so its player gets an MP4 of the
// sound over a moving waveform. The waveform costs little, so long files still fit.
const EMBED_SOUND_BPS = 128_000
const EMBED_WAVE_BPS = 200_000

export function audioEmbedPlan(duration) {
  if (!(duration > 0)) return { skip: 'unknown length' }
  if ((EMBED_SOUND_BPS + EMBED_WAVE_BPS) * duration > EMBED_TARGET_BYTES * 8 * 0.92) return { skip: 'too long' }
  return {}
}

function videoCopyArgs(url, { videoBps, height }) {
  // The shorter side is capped at `height`, so portrait videos are limited the same way.
  // Even sizes, because H.264 in 4:2:0 needs them.
  const scale = `scale=w='if(gt(iw\\,ih)\\,-2\\,min(${height}\\,trunc(iw/2)*2))':h='if(gt(iw\\,ih)\\,min(${height}\\,trunc(ih/2)*2)\\,-2)'`
  return [
    '-i', url, '-map', '0:v:0', '-map', '0:a:0?', '-sn', '-dn',
    '-vf', `${scale},format=yuv420p`, '-fpsmax', '30',
    '-c:v', 'libx264', '-preset', 'faster', '-profile:v', 'high', '-crf', '23',
    '-maxrate', String(videoBps), '-bufsize', String(videoBps * 2),
    '-c:a', 'aac', '-b:a', String(EMBED_AUDIO_BPS), '-ac', '2',
  ]
}

function audioCopyArgs(url) {
  return [
    '-i', url,
    '-filter_complex', `[0:a:0]showwaves=s=960x540:mode=cline:rate=15:colors=${WAVE_COLOR}:scale=sqrt[w];color=c=${WAVE_BACKGROUND}:s=960x540:r=15[bg];[bg][w]overlay=shortest=1:format=auto,format=yuv420p[v]`,
    '-map', '[v]', '-map', '0:a:0',
    '-c:v', 'libx264', '-preset', 'faster', '-profile:v', 'high', '-crf', '28',
    '-maxrate', String(EMBED_WAVE_BPS), '-bufsize', String(EMBED_WAVE_BPS * 2),
    '-c:a', 'aac', '-b:a', String(EMBED_SOUND_BPS), '-ac', '2',
  ]
}

// Writes the copy of a video or sound file to `outPath`, which must be in memory (see
// embeds.js): the MP4 index can only be moved to the front, where Discord needs it, in a
// file ffmpeg can seek in. Returns { width, height } of the copy, or { skip: reason }.
export async function makeEmbedCopy(read, meta, config, outPath) {
  return withLoopback(read, meta.size, async (url) => {
    // Files uploaded before durations were recorded are measured now.
    const duration = meta.duration ?? (await probe(config, url))?.duration
    const plan = meta.kind === 'audio' ? audioEmbedPlan(duration) : embedPlan(duration)
    if (plan.skip) return plan
    const encoded = await run(config.ffmpegPath, [
      '-nostdin', '-v', 'error', ...INPUT_ARGS,
      ...(meta.kind === 'audio' ? audioCopyArgs(url) : videoCopyArgs(url, plan)),
      '-map_metadata', '-1', '-movflags', '+faststart', '-f', 'mp4', '-y', outPath,
    ], { timeoutMs: 30 * 60_000, background: true })
    if (!encoded) return { skip: 'encode failed' }
    if ((await stat(outPath)).size > EMBED_MAX_BYTES) return { skip: 'too big' }
    const probed = await run(config.ffprobePath, ['-v', 'error', '-print_format', 'json', '-show_streams', outPath])
    const info = probed ? probeInfo(probed) : {}
    if (!info.width || !info.height) return { skip: 'encode failed' }
    return { width: info.width, height: info.height }
  })
}
