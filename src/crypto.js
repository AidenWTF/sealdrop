// All cryptography lives here. Only Node's built-in crypto module is used.
import {
  createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, scrypt, timingSafeEqual,
} from 'node:crypto'

export const CHUNK_SIZE = 1024 * 1024
export const TAG_SIZE = 16

// A link token is 128 random bits, written in base58 so that links are short and have no
// look-alike characters or symbols. It is the only copy of the file's key material that is
// usable without the owner's password.
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const TOKEN_BYTES = 16
const TOKEN_LENGTH = 22 // the fewest base58 characters that can hold 128 bits

export const TOKEN_PATTERN = `[${BASE58}]{${TOKEN_LENGTH}}`

export function newToken() {
  let value = BigInt(`0x${randomBytes(TOKEN_BYTES).toString('hex')}`)
  let out = ''
  for (let i = 0; i < TOKEN_LENGTH; i++) {
    out = BASE58[Number(value % 58n)] + out
    value /= 58n
  }
  return out
}

export function parseToken(token) {
  if (typeof token !== 'string' || !new RegExp(`^${TOKEN_PATTERN}$`).test(token)) return null
  let value = 0n
  for (const char of token) value = value * 58n + BigInt(BASE58.indexOf(char))
  // 22 base58 characters can hold slightly more than 128 bits, and no real token does.
  if (value >= 1n << BigInt(TOKEN_BYTES * 8)) return null
  return Buffer.from(value.toString(16).padStart(TOKEN_BYTES * 2, '0'), 'hex')
}

const derive = (ikm, label, length = 32) =>
  Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(0), `sealdrop/v1/${label}`, length))

// The storage id is one-way derived from the token, so reading the disk reveals no link.
export function fileKeys(tokenBytes) {
  return {
    id: derive(tokenBytes, 'id', 16).toString('hex'),
    data: derive(tokenBytes, 'data'),
    meta: derive(tokenBytes, 'meta'),
    thumb: derive(tokenBytes, 'thumb'),
    // Seals the record of the Discord-sized copy. The copy's own chunks use a random key
    // kept inside that record, so a retried copy never reuses a chunk key.
    embed: derive(tokenBytes, 'embed'),
  }
}

// Sealed blob layout: iv(12) | tag(16) | ciphertext
export function seal(key, plaintext, aad = '') {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(Buffer.from(aad))
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([iv, cipher.getAuthTag(), body])
}

// Returns null when the key is wrong or the data was altered.
export function open(key, blob, aad = '') {
  if (blob.length < 12 + TAG_SIZE) return null
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12))
    decipher.setAAD(Buffer.from(aad))
    decipher.setAuthTag(blob.subarray(12, 12 + TAG_SIZE))
    return Buffer.concat([decipher.update(blob.subarray(12 + TAG_SIZE)), decipher.final()])
  } catch {
    return null
  }
}

// Chunks are bound to their position and to whether they are last, so they can't be
// reordered, swapped or truncated. Each data key encrypts each index exactly once,
// which makes the counter nonce safe.
function chunkParams(index, isFinal) {
  const nonce = Buffer.alloc(12)
  nonce.writeBigUInt64BE(BigInt(index), 4)
  const aad = Buffer.alloc(9)
  aad.writeBigUInt64BE(BigInt(index), 0)
  aad[8] = isFinal ? 1 : 0
  return { nonce, aad }
}

export function sealChunk(key, index, isFinal, plaintext) {
  const { nonce, aad } = chunkParams(index, isFinal)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

// Throws when the chunk was altered, moved or truncated.
export function openChunk(key, index, isFinal, sealed) {
  const { nonce, aad } = chunkParams(index, isFinal)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(aad)
  decipher.setAuthTag(sealed.subarray(sealed.length - TAG_SIZE))
  return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - TAG_SIZE)), decipher.final()])
}

export const DEFAULT_KDF = { N: 2 ** 17, r: 8, p: 1 }

export function passwordKey(password, salt, { N, r, p }) {
  return new Promise((resolve, reject) => {
    scrypt(password.normalize('NFKC'), salt, 32, { N, r, p, maxmem: 256 * N * r }, (err, key) =>
      err ? reject(err) : resolve(key))
  })
}

export const sha256 = (value) => createHash('sha256').update(value).digest('hex')

export function safeEqual(a, b) {
  const left = Buffer.from(String(a))
  const right = Buffer.from(String(b))
  return left.length === right.length && timingSafeEqual(left, right)
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32Encode(bytes) {
  let bits = 0, value = 0, out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
    value &= (1 << bits) - 1
  }
  return bits > 0 ? out + BASE32[(value << (5 - bits)) & 31] : out
}

// RFC 6238 TOTP (SHA-1, 6 digits, 30 second steps), the variant every authenticator app supports.
export function totpCode(secret, step) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const mac = createHmac('sha1', secret).update(counter).digest()
  const offset = mac[mac.length - 1] & 15
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

// Returns the matched step, or null. Codes at or before lastStep are refused, so a
// code can never be used twice, even one observed by an attacker.
export function verifyTotp(secret, code, nowMs, lastStep = -1) {
  const current = Math.floor(nowMs / 30_000)
  let matched = null
  for (const step of [current - 1, current, current + 1]) {
    if (safeEqual(totpCode(secret, step), code) && step > lastStep) matched = step
  }
  return matched
}
