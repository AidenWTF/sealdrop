// HTTP helpers shared by the public server and the preview loopback.
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'

// Returns null to serve the whole file, 'invalid' for an unsatisfiable range, or [start, end].
export function parseRange(header, size) {
  if (!header || size === 0) return null
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim())
  if (!match || (match[1] === '' && match[2] === '')) return null
  if (match[1] === '') {
    const suffix = Number(match[2])
    return suffix === 0 ? 'invalid' : [Math.max(size - suffix, 0), size - 1]
  }
  const start = Number(match[1])
  const end = match[2] === '' ? size - 1 : Math.min(Number(match[2]), size - 1)
  return start >= size || start > end ? 'invalid' : [start, end]
}

// Decrypted bytes are streamed chunk by chunk with backpressure. If a chunk fails
// authentication the connection is cut, so altered data is never delivered as if intact.
export async function sendBytes(req, res, { size, read, headers }) {
  const range = parseRange(req.headers.range, size)
  if (range === 'invalid') {
    res.writeHead(416, { ...headers, 'Content-Range': `bytes */${size}`, 'Content-Length': 0 })
    res.end()
    return
  }
  const [start, end] = range ?? [0, size - 1]
  const length = size === 0 ? 0 : end - start + 1
  res.writeHead(range ? 206 : 200, {
    ...headers,
    'Accept-Ranges': 'bytes',
    'Content-Length': length,
    ...(range ? { 'Content-Range': `bytes ${start}-${end}/${size}` } : {}),
  })
  if (req.method === 'HEAD' || length === 0) {
    res.end()
    return
  }
  await pipeline(Readable.from(read(start, end), { highWaterMark: 1 }), res)
}

export function attachmentHeader(disposition, name) {
  const ascii = name.replace(/[^A-Za-z0-9._ -]/g, '_')
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
  return `${disposition}; filename="${ascii}"; filename*=UTF-8''${encoded}`
}

// File names come from a header, so they are cleaned before they are stored or shown.
export function cleanFileName(raw) {
  let name
  try {
    name = decodeURIComponent(String(raw ?? ''))
  } catch {
    name = ''
  }
  name = name.normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, '')
    .replace(/[/\\]/g, '_')
    .trim()
  name = Array.from(name).slice(0, 200).join('')
  return name === '' || name === '.' || name === '..' ? 'file' : name
}
