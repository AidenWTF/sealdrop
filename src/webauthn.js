// Passkeys (WebAuthn), with Node's built-in crypto only. This checks what the browser and
// authenticator signed; it doesn't judge the authenticator's make (attestation is "none"),
// since only the owner, already signed in, can add a passkey.
import { createHash, createPublicKey, timingSafeEqual, verify } from 'node:crypto'

export const b64url = (buffer) => Buffer.from(buffer).toString('base64url')
export const fromB64url = (text) => (typeof text === 'string' && /^[A-Za-z0-9_-]*$/.test(text) ? Buffer.from(text, 'base64url') : null)
const sha256 = (data) => createHash('sha256').update(data).digest()

// A minimal CBOR reader: enough for attestation objects and COSE keys. Returns [value, end].
export function decodeCbor(buffer, offset = 0, depth = 0) {
  if (depth > 16) throw new Error('cbor too deep')
  if (offset >= buffer.length) throw new Error('cbor truncated')
  const initial = buffer[offset]
  const major = initial >> 5
  const info = initial & 0x1f
  let pos = offset + 1
  let length
  if (info < 24) length = info
  else if (info === 24) length = buffer.readUInt8(pos++)
  else if (info === 25) { length = buffer.readUInt16BE(pos); pos += 2 }
  else if (info === 26) { length = buffer.readUInt32BE(pos); pos += 4 }
  else if (info === 27) {
    const big = buffer.readBigUInt64BE(pos)
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor number too large')
    length = Number(big)
    pos += 8
  } else throw new Error('cbor indefinite lengths are not supported')
  switch (major) {
    case 0: return [length, pos]
    case 1: return [-1 - length, pos]
    case 2:
    case 3: {
      if (pos + length > buffer.length) throw new Error('cbor truncated')
      const bytes = buffer.subarray(pos, pos + length)
      return [major === 2 ? Buffer.from(bytes) : bytes.toString('utf8'), pos + length]
    }
    case 4: {
      const items = []
      for (let i = 0; i < length; i++) {
        const [item, next] = decodeCbor(buffer, pos, depth + 1)
        items.push(item)
        pos = next
      }
      return [items, pos]
    }
    case 5: {
      const map = new Map()
      for (let i = 0; i < length; i++) {
        const [key, afterKey] = decodeCbor(buffer, pos, depth + 1)
        const [value, afterValue] = decodeCbor(buffer, afterKey, depth + 1)
        map.set(key, value)
        pos = afterValue
      }
      return [map, pos]
    }
    case 7:
      if (info === 20) return [false, pos]
      if (info === 21) return [true, pos]
      if (info === 22) return [null, pos]
      throw new Error('cbor value not supported')
    default:
      throw new Error('cbor tags are not supported')
  }
}

const FLAG_USER_PRESENT = 0x01
const FLAG_USER_VERIFIED = 0x04
const FLAG_ATTESTED = 0x40

function parseAuthData(data) {
  if (!Buffer.isBuffer(data) || data.length < 37) throw new Error('authenticator data too short')
  const result = { rpIdHash: data.subarray(0, 32), flags: data[32], signCount: data.readUInt32BE(33) }
  if (result.flags & FLAG_ATTESTED) {
    if (data.length < 55) throw new Error('authenticator data too short')
    const idLength = data.readUInt16BE(53)
    if (idLength < 16 || idLength > 1023 || data.length < 55 + idLength) throw new Error('bad credential id')
    result.credentialId = Buffer.from(data.subarray(55, 55 + idLength))
    const [cose] = decodeCbor(data, 55 + idLength)
    result.cose = cose
  }
  return result
}

// The algorithms passkeys use in practice: ES256 (almost all), EdDSA and RS256.
export const ALGORITHMS = [-7, -8, -257]

function coseToPublicKey(cose) {
  if (!(cose instanceof Map)) throw new Error('bad public key')
  const kty = cose.get(1)
  const alg = cose.get(3)
  let jwk
  if (kty === 2 && alg === -7 && cose.get(-1) === 1) {
    const x = cose.get(-2)
    const y = cose.get(-3)
    if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) throw new Error('bad public key')
    jwk = { kty: 'EC', crv: 'P-256', x: b64url(x), y: b64url(y) }
  } else if (kty === 1 && alg === -8 && cose.get(-1) === 6) {
    const x = cose.get(-2)
    if (!Buffer.isBuffer(x) || x.length !== 32) throw new Error('bad public key')
    jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(x) }
  } else if (kty === 3 && alg === -257) {
    const n = cose.get(-1)
    const e = cose.get(-2)
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e) || n.length < 256) throw new Error('bad public key')
    jwk = { kty: 'RSA', n: b64url(n), e: b64url(e) }
  } else {
    throw new Error('unsupported key type')
  }
  const key = createPublicKey({ key: jwk, format: 'jwk' })
  return { alg, publicKey: key.export({ type: 'spki', format: 'der' }).toString('base64') }
}

function checkClientData(clientDataJSON, type, expected) {
  if (!Buffer.isBuffer(clientDataJSON) || clientDataJSON.length > 4096) throw new Error('bad client data')
  const data = JSON.parse(clientDataJSON.toString('utf8'))
  if (data.type !== type) throw new Error('wrong ceremony')
  const challenge = fromB64url(data.challenge)
  if (!challenge || challenge.length !== expected.challenge.length || !timingSafeEqual(challenge, expected.challenge)) {
    throw new Error('wrong challenge')
  }
  if (data.origin !== expected.origin) throw new Error('wrong origin')
  if (data.crossOrigin === true) throw new Error('cross-origin')
}

function checkAuthData(auth, expected) {
  if (!timingSafeEqual(auth.rpIdHash, sha256(expected.rpId))) throw new Error('wrong site')
  if (!(auth.flags & FLAG_USER_PRESENT)) throw new Error('user not present')
  if (expected.requireUserVerification && !(auth.flags & FLAG_USER_VERIFIED)) throw new Error('user not verified')
}

// `response` holds base64url fields from the browser. Returns the new passkey's record.
export function verifyRegistration(response, expected) {
  const clientDataJSON = fromB64url(response?.clientDataJSON)
  const attestationObject = fromB64url(response?.attestationObject)
  if (!clientDataJSON || !attestationObject) throw new Error('missing fields')
  checkClientData(clientDataJSON, 'webauthn.create', expected)
  const [attestation] = decodeCbor(attestationObject)
  if (!(attestation instanceof Map) || !Buffer.isBuffer(attestation.get('authData'))) throw new Error('bad attestation')
  const auth = parseAuthData(attestation.get('authData'))
  checkAuthData(auth, expected)
  if (!auth.credentialId) throw new Error('no credential')
  return { id: b64url(auth.credentialId), ...coseToPublicKey(auth.cose), signCount: auth.signCount }
}

// Returns { passkey, signCount } for the stored passkey that signed, or throws.
export function verifyAssertion(response, expected, passkeys) {
  const passkey = passkeys.find((p) => p.id === response?.id)
  if (!passkey) throw new Error('unknown passkey')
  const clientDataJSON = fromB64url(response.clientDataJSON)
  const authenticatorData = fromB64url(response.authenticatorData)
  const signature = fromB64url(response.signature)
  if (!clientDataJSON || !authenticatorData || !signature) throw new Error('missing fields')
  checkClientData(clientDataJSON, 'webauthn.get', expected)
  const auth = parseAuthData(authenticatorData)
  checkAuthData(auth, expected)
  const key = createPublicKey({ key: Buffer.from(passkey.publicKey, 'base64'), format: 'der', type: 'spki' })
  const signed = Buffer.concat([authenticatorData, sha256(clientDataJSON)])
  const ok = verify(passkey.alg === -8 ? null : 'sha256', signed, key, signature)
  if (!ok) throw new Error('bad signature')
  // A counter that goes backwards means a cloned authenticator. Synced passkeys report 0.
  if (auth.signCount !== 0 && auth.signCount <= passkey.signCount) throw new Error('counter went backwards')
  return { passkey, signCount: auth.signCount }
}
