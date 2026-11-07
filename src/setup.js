// Creates or updates the owner identity. This command, run on the server itself, is the
// only way an owner can come into existence.
import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { Writable } from 'node:stream'
import { DEVICES_FILE } from './auth.js'
import { loadConfig } from './config.js'
import { base32Encode, verifyTotp } from './crypto.js'
import { loadOwner, newSecrets, ownerPath, unlockOwner, writeOwner } from './owner.js'

process.umask(0o077)
const config = loadConfig()
await mkdir(config.dataDir, { recursive: true, mode: 0o700 })

let muted = false
const output = new Writable({
  write(chunk, encoding, done) {
    if (!muted) process.stdout.write(chunk, encoding)
    done()
  },
})
const rl = createInterface({ input: process.stdin, output, terminal: Boolean(process.stdin.isTTY) })
const lines = rl[Symbol.asyncIterator]()

async function ask(prompt, { hidden = false } = {}) {
  process.stdout.write(prompt)
  muted = hidden
  const { value, done } = await lines.next()
  muted = false
  if (hidden) process.stdout.write('\n')
  if (done) {
    console.error('Input ended unexpectedly.')
    process.exit(1)
  }
  return value
}

async function choosePassword() {
  const first = await ask('New password (leave blank to generate a strong one): ', { hidden: true })
  if (first === '') {
    const generated = randomBytes(24).toString('base64url')
    console.log(`\nYour password, shown only once. Save it in a password manager now:\n\n  ${generated}\n`)
    return generated
  }
  if (Array.from(first).length < 14) {
    console.error('Use at least 14 characters.')
    process.exit(1)
  }
  if (first !== await ask('Repeat password: ', { hidden: true })) {
    console.error('The passwords did not match.')
    process.exit(1)
  }
  return first
}

async function enrollAuthenticator(secret) {
  const encoded = base32Encode(secret)
  const uri = `otpauth://totp/${encodeURIComponent(config.siteName)}?secret=${encoded}&issuer=${encodeURIComponent(config.siteName)}&algorithm=SHA1&digits=6&period=30`
  console.log('\nAdd this to your authenticator app (Aegis, 1Password, Google Authenticator...).')
  const qr = spawnSync('qrencode', ['-t', 'ANSIUTF8', uri], { stdio: ['ignore', 'pipe', 'ignore'] })
  if (qr.status === 0) console.log(`\n${qr.stdout.toString()}`)
  console.log(`\nManual entry key: ${encoded}\n`)
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = (await ask('Enter the 6-digit code it shows, to confirm it works: ')).trim()
    if (verifyTotp(secret, code, Date.now()) !== null) return
    console.log('That code did not match. Check the entry and your device clock.')
  }
  console.error('Could not confirm the authenticator. Nothing was changed.')
  process.exit(1)
}

const reset = process.argv.includes('--reset')
const path = ownerPath(config.dataDir)
const existed = existsSync(path)
let secrets

if (existed && !reset) {
  console.log('An owner already exists. Changing the password and authenticator requires the current password.')
  const unlocked = await unlockOwner(await loadOwner(config.dataDir), await ask('Current password: ', { hidden: true }))
  if (!unlocked) {
    console.error('Wrong password. Nothing was changed.')
    process.exit(1)
  }
  // The master key is kept, so the dashboard still lists every existing file.
  secrets = { masterKey: unlocked.masterKey, totpSecret: randomBytes(20) }
} else {
  if (reset && existed) {
    console.log('RESET: this replaces the owner. Existing links keep working, but those files disappear from your dashboard for good.')
    if (await ask('Type RESET to continue: ') !== 'RESET') {
      console.log('Nothing was changed.')
      process.exit(0)
    }
  }
  secrets = newSecrets()
}

const password = await choosePassword()
await enrollAuthenticator(secrets.totpSecret)
await writeOwner(config.dataDir, password, secrets)
await rm(join(config.dataDir, DEVICES_FILE), { force: true })
console.log(existed
  ? `\nOwner saved to ${path}. Restart the server for this to take effect.`
  : `\nOwner saved to ${path}. A server waiting for setup starts the site within a few seconds.`)
rl.close()
