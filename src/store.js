// Encrypted file storage. On disk each upload is files/<id>/ holding:
//   data   AES-256-GCM chunks, keyed by the link token
//   meta   sealed JSON (name, size, type...), keyed by the link token
//   thumb  sealed JPEG preview, keyed by the link token
//   owner  the link token sealed with the owner's master key, for the dashboard
// Plaintext is never written to disk, not even temporarily.
import { createHash, randomBytes } from 'node:crypto'
import { mkdir, open as openFile, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { CHUNK_SIZE, TAG_SIZE, fileKeys, newToken, open, openChunk, parseToken, seal, sealChunk } from './crypto.js'

const PRIVATE = { mode: 0o600 }

export async function* readRange(path, key, size, start, end) {
  if (size === 0) return
  const lastIndex = Math.ceil(size / CHUNK_SIZE) - 1
  const handle = await openFile(path, 'r')
  try {
    for (let index = Math.floor(start / CHUNK_SIZE); index <= Math.floor(end / CHUNK_SIZE); index++) {
      const plainLength = index === lastIndex ? size - index * CHUNK_SIZE : CHUNK_SIZE
      const sealed = Buffer.allocUnsafe(plainLength + TAG_SIZE)
      const { bytesRead } = await handle.read(sealed, 0, sealed.length, index * (CHUNK_SIZE + TAG_SIZE))
      if (bytesRead !== sealed.length) throw new Error('truncated data')
      const plain = openChunk(key, index, index === lastIndex, sealed)
      const base = index * CHUNK_SIZE
      yield plain.subarray(Math.max(start - base, 0), Math.min(end - base + 1, plain.length))
    }
  } finally {
    await handle.close()
  }
}

class Upload {
  size = 0
  head = Buffer.alloc(0)
  #buffer = Buffer.allocUnsafe(CHUNK_SIZE)
  #filled = 0
  #index = 0
  #md5 = createHash('md5')

  constructor(store, dir, handle) {
    this.store = store
    this.dir = dir
    this.handle = handle
    this.token = newToken()
    this.keys = fileKeys(parseToken(this.token))
  }

  async write(data) {
    if (this.head.length < 4096) this.head = Buffer.concat([this.head, data.subarray(0, 4096 - this.head.length)])
    this.size += data.length
    this.#md5.update(data)
    let offset = 0
    while (offset < data.length) {
      // A full buffer is held until more data arrives, because only then is it known not to be last.
      if (this.#filled === CHUNK_SIZE) await this.#flush(false)
      const copied = data.copy(this.#buffer, this.#filled, offset)
      this.#filled += copied
      offset += copied
    }
  }

  async #flush(isFinal) {
    const sealed = sealChunk(this.keys.data, this.#index++, isFinal, this.#buffer.subarray(0, this.#filled))
    await this.handle.write(sealed)
    this.#filled = 0
  }

  async finishData() {
    await this.#flush(true)
    await this.handle.close()
    this.handle = null
    this.md5 = this.#md5.digest('hex')
  }

  reader() {
    const path = join(this.dir, 'data')
    return (start, end) => readRange(path, this.keys.data, this.size, start, end)
  }

  // The master key is passed in so that nothing can be stored without a logged-in owner:
  // it exists only in the memory of an authenticated session.
  async commit(meta, thumb, masterKey) {
    const ownerBlob = seal(masterKey, this.token, this.keys.id)
    await writeFile(join(this.dir, 'meta'), seal(this.keys.meta, JSON.stringify(meta)), PRIVATE)
    if (thumb) await writeFile(join(this.dir, 'thumb'), seal(this.keys.thumb, thumb), PRIVATE)
    await writeFile(join(this.dir, 'owner'), ownerBlob, PRIVATE)
    await rename(this.dir, join(this.store.filesDir, this.keys.id))
    this.dir = null
  }

  async abort() {
    if (this.handle) await this.handle.close().catch(() => {})
    if (this.dir) await rm(this.dir, { recursive: true, force: true })
  }
}

export class Store {
  constructor(dataDir) {
    this.filesDir = join(dataDir, 'files')
    this.tmpDir = join(dataDir, 'tmp')
  }

  async init() {
    await mkdir(this.filesDir, { recursive: true, mode: 0o700 })
    await rm(this.tmpDir, { recursive: true, force: true })
    await mkdir(this.tmpDir, { recursive: true, mode: 0o700 })
  }

  async beginUpload() {
    const dir = join(this.tmpDir, randomBytes(16).toString('hex'))
    await mkdir(dir, { mode: 0o700 })
    return new Upload(this, dir, await openFile(join(dir, 'data'), 'wx', 0o600))
  }

  // Returns null for anything that isn't a stored file, with no distinction between
  // malformed, never existed, deleted and tampered.
  async load(token) {
    const bytes = parseToken(token)
    if (!bytes) return null
    const keys = fileKeys(bytes)
    const dir = join(this.filesDir, keys.id)
    let blob
    try {
      blob = await readFile(join(dir, 'meta'))
    } catch {
      return null
    }
    const plain = open(keys.meta, blob)
    if (!plain) return null
    const meta = JSON.parse(plain.toString('utf8'))
    return {
      token, keys, dir, meta,
      read: (start, end) => readRange(join(dir, 'data'), keys.data, meta.size, start, end),
    }
  }

  async thumb(file) {
    try {
      return open(file.keys.thumb, await readFile(join(file.dir, 'thumb')))
    } catch {
      return null
    }
  }

  async list(masterKey) {
    const files = []
    for (const id of await readdir(this.filesDir)) {
      let blob
      try {
        blob = await readFile(join(this.filesDir, id, 'owner'))
      } catch {
        continue
      }
      const token = open(masterKey, blob, id)?.toString('utf8')
      const file = token && await this.load(token)
      if (file && file.keys.id === id) files.push(file)
    }
    return files.sort((a, b) => b.meta.createdAt - a.meta.createdAt)
  }

  async remove(token) {
    const file = await this.load(token)
    if (!file) return false
    await rm(file.dir, { recursive: true, force: true })
    return true
  }
}
