// Removes location and other personal metadata from JPEG photos as they upload, before
// anything is stored. Kept: what the picture needs to look right, which is JFIF, the colour
// profile (ICC), Adobe's colour transform and, rebuilt on its own, the orientation.
// Dropped: EXIF (location, camera, times), XMP, IPTC/Photoshop, comments, vendor blocks,
// the multi-picture index, and anything after the image ends, where phones keep motion
// photo videos and other extra images that carry their own metadata.

const MAX_HEADER = 16 * 1024 * 1024
const KEEP = new Set([0xe0, 0xe2, 0xee]) // APP0 JFIF, APP2 ICC (MPF filtered below), APP14 Adobe
const NO_LENGTH = (marker) => marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)

export class MetadataError extends Error {}

// The orientation from an EXIF block, or null.
export function exifOrientation(payload) {
  if (payload.length < 14 || payload.toString('latin1', 0, 6) !== 'Exif\0\0') return null
  const tiff = payload.subarray(6)
  const little = tiff.toString('latin1', 0, 2) === 'II'
  if (!little && tiff.toString('latin1', 0, 2) !== 'MM') return null
  const u16 = (at) => (little ? tiff.readUInt16LE(at) : tiff.readUInt16BE(at))
  const u32 = (at) => (little ? tiff.readUInt32LE(at) : tiff.readUInt32BE(at))
  try {
    const ifd = u32(4)
    const count = u16(ifd)
    for (let i = 0; i < count; i++) {
      const entry = ifd + 2 + i * 12
      if (u16(entry) === 0x0112) {
        const value = u16(entry + 8)
        return value >= 1 && value <= 8 ? value : null
      }
    }
  } catch {
    return null
  }
  return null
}

// A minimal EXIF block holding only the orientation.
export function orientationSegment(orientation) {
  const body = Buffer.alloc(32)
  body.write('Exif\0\0', 0, 'latin1')
  body.write('MM\0*', 6, 'latin1')
  body.writeUInt32BE(8, 10) // first IFD right after the header
  body.writeUInt16BE(1, 14) // one entry
  body.writeUInt16BE(0x0112, 16) // Orientation
  body.writeUInt16BE(3, 18) // SHORT
  body.writeUInt32BE(1, 20) // one value
  body.writeUInt16BE(orientation, 24)
  body.writeUInt32BE(0, 28) // no next IFD
  return Buffer.concat([Buffer.from([0xff, 0xe1, 0, body.length + 2]), body])
}

// Takes the upload's chunks and yields the cleaned file. Anything that isn't a JPEG
// passes through untouched.
export async function* cleanJpeg(source) {
  const iterator = source[Symbol.asyncIterator]()
  try {
    yield* clean(iterator)
  } finally {
    await iterator.return?.() // the upload stops being read if the consumer stops early
  }
}

async function* clean(iterator) {
  let buffer = Buffer.alloc(0)
  let done = false
  const fill = async (needed) => {
    while (!done && buffer.length < needed) {
      const next = await iterator.next()
      if (next.done) done = true
      else buffer = Buffer.concat([buffer, next.value])
      if (buffer.length > MAX_HEADER) throw new MetadataError('photo headers too large')
    }
    return buffer.length >= needed
  }

  await fill(3)
  if (buffer.length < 3 || buffer[0] !== 0xff || buffer[1] !== 0xd8 || buffer[2] !== 0xff) {
    yield buffer
    for (let next = await iterator.next(); !next.done; next = await iterator.next()) yield next.value
    return
  }

  // Header segments, up to the start of the image data.
  const kept = [Buffer.from([0xff, 0xd8])]
  let orientation = null
  let pos = 2
  for (;;) {
    if (!await fill(pos + 2)) throw new MetadataError('photo ends early')
    if (buffer[pos] !== 0xff) throw new MetadataError('not a valid photo')
    if (buffer[pos + 1] === 0xff) { pos++; continue } // fill byte
    const marker = buffer[pos + 1]
    if (NO_LENGTH(marker)) { pos += 2; continue }
    if (!await fill(pos + 4)) throw new MetadataError('photo ends early')
    const length = buffer.readUInt16BE(pos + 2)
    if (length < 2 || !await fill(pos + 2 + length)) throw new MetadataError('photo ends early')
    const segment = buffer.subarray(pos, pos + 2 + length)
    const payload = segment.subarray(4)
    if (marker === 0xda) {
      // Start of image data: everything from here is the picture itself.
      if (orientation) kept.push(orientationSegment(orientation))
      kept.push(segment)
      pos += 2 + length
      break
    }
    if (marker === 0xe1) orientation ??= exifOrientation(payload)
    const isApp = (marker >= 0xe0 && marker <= 0xef) || marker === 0xfe
    const isMpf = marker === 0xe2 && payload.toString('latin1', 0, 4) === 'MPF\0'
    if (!isApp || (KEEP.has(marker) && !isMpf)) kept.push(segment)
    pos += 2 + length
  }
  yield Buffer.concat(kept)

  // Image data, up to and including the end marker. Bytes after it are dropped.
  let rest = buffer.subarray(pos)
  let previousFF = false
  for (;;) {
    let end = -1
    for (let i = 0; i < rest.length; i++) {
      const isEnd = rest[i] === 0xd9 && (i === 0 ? previousFF : rest[i - 1] === 0xff)
      if (isEnd) { end = i + 1; break }
    }
    if (end >= 0) {
      yield rest.subarray(0, end)
      break
    }
    if (rest.length) yield rest
    previousFF = rest.length ? rest[rest.length - 1] === 0xff : previousFF
    const next = await iterator.next()
    if (next.done) return
    rest = next.value
  }
  // Read the rest of the upload so the request completes, without keeping it.
  for (let next = await iterator.next(); !next.done; next = await iterator.next()) { /* dropped */ }
}
