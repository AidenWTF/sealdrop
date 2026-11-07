// Short links. On disk each is links/<id>/ holding:
//   target  the destination, sealed with a key from the code
//   owner   the code, sealed with its creator's master key, for their dashboard
// So the disk shows how many short links exist, but not where they go or what they are.
import { mkdir, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { SHORT_PATTERN, newShortCode, open, seal, shortLinkKeys } from './crypto.js'

const PRIVATE = { mode: 0o600 }
const CODE = new RegExp(`^${SHORT_PATTERN}$`)
export const MAX_URL_LENGTH = 2048

// Only web addresses: no javascript:, data: or other schemes, and nothing with a password.
export function cleanTarget(value) {
  if (typeof value !== 'string' || value.length > MAX_URL_LENGTH) return null
  let url
  try {
    url = new URL(value.trim())
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  if (url.username || url.password) return null
  return url.href
}

export class Links {
  constructor(dataDir) {
    this.dir = join(dataDir, 'links')
  }

  async init() {
    await mkdir(this.dir, { recursive: true, mode: 0o700 })
  }

  async create(url, masterKey, time) {
    const code = newShortCode()
    const keys = shortLinkKeys(code)
    const temp = join(this.dir, `.${keys.id}.tmp`)
    await mkdir(temp, { mode: 0o700 })
    await writeFile(join(temp, 'target'), seal(keys.target, JSON.stringify({ url, createdAt: time }), 'short-target'), PRIVATE)
    await writeFile(join(temp, 'owner'), seal(masterKey, code, keys.id), PRIVATE)
    await rename(temp, join(this.dir, keys.id))
    return { code, url, createdAt: time }
  }

  // The destination, or null for anything that isn't a stored short link.
  async resolve(code) {
    if (typeof code !== 'string' || !CODE.test(code)) return null
    const keys = shortLinkKeys(code)
    try {
      const plain = open(keys.target, await readFile(join(this.dir, keys.id, 'target')), 'short-target')
      return plain ? JSON.parse(plain.toString('utf8')) : null
    } catch {
      return null
    }
  }

  async list(masterKey) {
    const found = []
    for (const id of await readdir(this.dir).catch(() => [])) {
      if (id.startsWith('.')) continue
      const code = await readFile(join(this.dir, id, 'owner')).then((blob) => open(masterKey, blob, id)?.toString('utf8'), () => null)
      if (!code || shortLinkKeys(code).id !== id) continue
      const target = await this.resolve(code)
      if (target) found.push({ code, ...target })
    }
    return found.sort((a, b) => b.createdAt - a.createdAt)
  }

  // Only the creator can remove a short link.
  async remove(code, masterKey) {
    if (typeof code !== 'string' || !CODE.test(code)) return false
    const { id } = shortLinkKeys(code)
    const owned = await readFile(join(this.dir, id, 'owner')).then((blob) => open(masterKey, blob, id)?.toString('utf8') === code, () => false)
    if (!owned) return false
    await rm(join(this.dir, id), { recursive: true, force: true })
    return true
  }
}
