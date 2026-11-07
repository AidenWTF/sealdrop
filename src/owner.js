// The owner identity is one file, written only by the setup command. No web route can
// create or change it. The password is verified by decrypting the vault, so the file
// holds no password hash and the TOTP secret can't be read without the password.
import { randomBytes } from 'node:crypto'
import { chmod, readFile, rename, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { DEFAULT_KDF, open, passwordKey, seal } from './crypto.js'

export const ownerPath = (dataDir) => join(dataDir, 'owner.json')

export async function writeOwner(dataDir, password, secrets, kdf = DEFAULT_KDF) {
  const salt = randomBytes(16)
  const key = await passwordKey(password, salt, kdf)
  const vault = seal(key, JSON.stringify({
    masterKey: secrets.masterKey.toString('base64'),
    totpSecret: secrets.totpSecret.toString('base64'),
  }), 'owner-vault')
  const path = ownerPath(dataDir)
  const temp = `${path}.${randomBytes(4).toString('hex')}`
  await writeFile(temp, JSON.stringify({
    v: 1, kdf: { ...kdf, salt: salt.toString('base64') }, vault: vault.toString('base64'),
  }), { mode: 0o600 })
  await rename(temp, path)
  await chmod(path, 0o600)
}

export const newSecrets = () => ({ masterKey: randomBytes(32), totpSecret: randomBytes(20) })

export async function loadOwner(dataDir) {
  const path = ownerPath(dataDir)
  const info = await stat(path)
  if (info.mode & 0o077) throw new Error(`${path} must be readable only by its owner (chmod 600)`)
  return JSON.parse(await readFile(path, 'utf8'))
}

// Returns the secrets, or null when the password is wrong.
export async function unlockOwner(owner, password) {
  const key = await passwordKey(password, Buffer.from(owner.kdf.salt, 'base64'), owner.kdf)
  const plain = open(key, Buffer.from(owner.vault, 'base64'), 'owner-vault')
  if (!plain) return null
  const parsed = JSON.parse(plain.toString('utf8'))
  return {
    masterKey: Buffer.from(parsed.masterKey, 'base64'),
    totpSecret: Buffer.from(parsed.totpSecret, 'base64'),
  }
}
