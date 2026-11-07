// The owner's passkeys and whether authenticator codes still work, in passkeys.json.
// Public keys aren't secret, but the list must not be changeable by someone who can only
// write to the disk, so it carries an HMAC under a key derived from the master key.
import { createHmac, timingSafeEqual } from 'node:crypto'
import { readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { passkeyListKey } from './crypto.js'

export const PASSKEYS_FILE = 'passkeys.json'
export const MAX_PASSKEYS = 10
// A new object every time: callers add to the list they get back.
const empty = () => ({ passkeys: [], codesAllowed: true })

const mac = (masterKey, body) => createHmac('sha256', passkeyListKey(masterKey)).update(JSON.stringify(body)).digest()

// Without the master key: only for deciding what the login page shows. Never trusted.
export async function passkeyHints(dataDir) {
  try {
    const { body } = JSON.parse(await readFile(join(dataDir, PASSKEYS_FILE), 'utf8'))
    return { hasPasskeys: body.passkeys.length > 0, codesAllowed: body.codesAllowed !== false }
  } catch {
    return { hasPasskeys: false, codesAllowed: true }
  }
}

// Returns { passkeys, codesAllowed, tampered }. A list that fails its check is ignored,
// and codes work, so the owner can still sign in and see what happened.
export async function readPasskeys(dataDir, masterKey) {
  let stored
  try {
    stored = JSON.parse(await readFile(join(dataDir, PASSKEYS_FILE), 'utf8'))
  } catch (err) {
    return { ...empty(), tampered: err.code !== 'ENOENT' }
  }
  if (!Array.isArray(stored?.body?.passkeys)) return { ...empty(), tampered: true }
  const expected = mac(masterKey, stored.body)
  const actual = Buffer.from(String(stored.mac ?? ''), 'base64')
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return { ...empty(), tampered: true }
  return { passkeys: stored.body.passkeys, codesAllowed: stored.body.codesAllowed !== false, tampered: false }
}

export async function writePasskeys(dataDir, masterKey, { passkeys, codesAllowed }) {
  // Codes can only be off while there is a passkey to sign in with.
  const body = { passkeys, codesAllowed: passkeys.length === 0 ? true : codesAllowed }
  const path = join(dataDir, PASSKEYS_FILE)
  const temp = `${path}.tmp`
  await writeFile(temp, JSON.stringify({ v: 1, body, mac: mac(masterKey, body).toString('base64') }), { mode: 0o600 })
  await rename(temp, path)
}

export const removePasskeyFile = (dataDir) => rm(join(dataDir, PASSKEYS_FILE), { force: true })
