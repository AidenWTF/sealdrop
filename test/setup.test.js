import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { chmod, mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { totpCode } from '../src/crypto.js'
import { loadOwner, ownerPath, unlockOwner, newSecrets, writeOwner } from '../src/owner.js'
import { loadConfig } from '../src/config.js'

const root = fileURLToPath(new URL('..', import.meta.url))
const PASSWORD = 'a long enough test password'

function decodeBase32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const char of text) bits += alphabet.indexOf(char).toString(2).padStart(5, '0')
  return Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
}

// Drives the real setup command, answering prompts as they appear.
function runSetup(dataDir, answer, args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['src/setup.js', ...args], {
      cwd: root, env: { ...process.env, DATA_DIR: dataDir, PUBLIC_URL: 'https://files.example.com' },
    })
    let output = ''
    let answered = 0
    const onData = (piece) => {
      output += piece
      const reply = answer(output, answered)
      if (reply !== null) {
        answered++
        child.stdin.write(`${reply}\n`)
      }
    }
    child.stdout.on('data', onData)
    child.stderr.on('data', (piece) => { output += piece })
    child.on('close', (code) => resolve({ code, output }))
  })
}

const freshAnswers = (password, repeat = password) => (output, answered) => {
  if (answered === 0 && output.includes('New password')) return password
  if (answered === 1 && output.includes('Repeat password')) return repeat
  if (answered === 2 && output.includes('Enter the 6-digit')) {
    const key = /Manual entry key: ([A-Z2-7]+)/.exec(output)[1]
    return totpCode(decodeBase32(key), Math.floor(Date.now() / 30_000))
  }
  return null
}

async function tempDir(t) {
  const dir = await mkdtemp(join(tmpdir(), 'sealdrop-setup-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  return dir
}

test('setup creates an owner only after the authenticator is confirmed', async (t) => {
  const dir = await tempDir(t)
  const { code } = await runSetup(dir, freshAnswers(PASSWORD))
  assert.equal(code, 0)
  assert.equal((await stat(ownerPath(dir))).mode & 0o777, 0o600)
  const owner = await loadOwner(dir)
  assert.ok(await unlockOwner(owner, PASSWORD))
  assert.equal(await unlockOwner(owner, 'not the password at all'), null)
  assert.ok(owner.kdf.N >= 2 ** 17, 'real setups use the strong KDF cost')
})

test('setup refuses weak or mismatched passwords and writes nothing', async (t) => {
  const dir = await tempDir(t)
  const weak = await runSetup(dir, freshAnswers('short'))
  assert.equal(weak.code, 1)
  const mismatch = await runSetup(dir, freshAnswers(PASSWORD, `${PASSWORD}x`))
  assert.equal(mismatch.code, 1)
  await assert.rejects(stat(ownerPath(dir)))
})

test('an existing owner cannot be replaced without the current password', async (t) => {
  const dir = await tempDir(t)
  const secrets = newSecrets()
  await writeOwner(dir, PASSWORD, secrets, { N: 2 ** 12, r: 8, p: 1 })
  const { code, output } = await runSetup(dir, (text, answered) => (answered === 0 && text.includes('Current password') ? 'wrong password' : null))
  assert.equal(code, 1)
  assert.match(output, /Nothing was changed/)
  assert.ok(await unlockOwner(await loadOwner(dir), PASSWORD))
})

test('changing the password keeps the master key, so files stay listed', async (t) => {
  const dir = await tempDir(t)
  const secrets = newSecrets()
  await writeOwner(dir, PASSWORD, secrets, { N: 2 ** 12, r: 8, p: 1 })
  await writeFile(join(dir, 'devices.json'), '{"devices":["old"]}')
  const next = 'a different long test password'
  const fresh = freshAnswers(next)
  const { code } = await runSetup(dir, (text, answered) => {
    if (answered === 0) return text.includes('Current password') ? PASSWORD : null
    return fresh(text, answered - 1)
  })
  assert.equal(code, 0)
  const owner = await loadOwner(dir)
  assert.equal(await unlockOwner(owner, PASSWORD), null)
  const unlocked = await unlockOwner(owner, next)
  assert.ok(unlocked.masterKey.equals(secrets.masterKey))
  assert.ok(!unlocked.totpSecret.equals(secrets.totpSecret), 'the authenticator secret is rotated')
  await assert.rejects(stat(join(dir, 'devices.json')), 'trusted browsers are forgotten')
})

test('the server refuses an owner file others can read', async (t) => {
  const dir = await tempDir(t)
  await writeOwner(dir, PASSWORD, newSecrets(), { N: 2 ** 12, r: 8, p: 1 })
  await chmod(ownerPath(dir), 0o644)
  await assert.rejects(loadOwner(dir), /chmod 600/)
  assert.ok(loadConfig({ DATA_DIR: dir }).dataDir === dir)
})

test('without an owner the server stays up, answers 503, and starts once setup is done', async (t) => {
  const dir = await tempDir(t)
  const child = spawn(process.execPath, ['src/main.js'], {
    cwd: root, env: { ...process.env, DATA_DIR: dir, PORT: '0', HOST: '127.0.0.1' },
  })
  const exited = new Promise((resolve) => child.on('close', resolve))
  t.after(() => child.kill('SIGKILL'))
  let output = ''
  const seen = (pattern) => new Promise((resolve, reject) => {
    const check = () => {
      const match = pattern.exec(output)
      if (match) {
        child.stdout.off('data', onData)
        child.stderr.off('data', onData)
        resolve(match)
      }
    }
    const onData = (piece) => { output += piece; check() }
    child.stdout.on('data', onData)
    child.stderr.on('data', onData)
    child.once('close', () => reject(new Error(`server exited early:\n${output}`)))
    check()
  })

  const [, waitingPort] = await seen(/Waiting for setup on [\d.]+:(\d+)/)
  const waiting = await fetch(`http://127.0.0.1:${waitingPort}/`)
  assert.equal(waiting.status, 503)
  assert.match(await waiting.text(), /not set up yet/)
  assert.equal(child.exitCode, null, 'it keeps running instead of exiting')
  assert.equal((await fetch(`http://127.0.0.1:${waitingPort}/healthz`)).status, 200, 'healthy while waiting, so it is not restarted')

  await writeOwner(dir, PASSWORD, newSecrets(), { N: 2 ** 12, r: 8, p: 1 })
  const [, appPort] = await seen(/listening on [\d.]+:(\d+)/)
  const ready = await fetch(`http://127.0.0.1:${appPort}/`, { redirect: 'manual' })
  assert.notEqual(ready.status, 503)
  await ready.arrayBuffer()

  child.kill('SIGTERM')
  assert.equal(await exited, 0)
})

test('running setup again turns codes back on, the way back in after losing every passkey', async (t) => {
  const { readPasskeys, writePasskeys } = await import('../src/passkeys.js')
  const dir = await tempDir(t)
  const secrets = newSecrets()
  await writeOwner(dir, PASSWORD, secrets, { N: 2 ** 12, r: 8, p: 1 })
  const passkey = { id: 'A'.repeat(43), alg: -7, publicKey: 'x', signCount: 0, name: 'Phone', createdAt: 0, lastUsedAt: null }
  await writePasskeys(dir, secrets.masterKey, { passkeys: [passkey], codesAllowed: false })

  const next = 'a different long test password'
  const fresh = freshAnswers(next)
  const { code, output } = await runSetup(dir, (text, answered) => {
    if (answered === 0) return text.includes('Current password') ? PASSWORD : null
    return fresh(text, answered - 1)
  })
  assert.equal(code, 0)
  assert.match(output, /codes are allowed again/)
  const after = await readPasskeys(dir, secrets.masterKey)
  assert.equal(after.tampered, false)
  assert.equal(after.codesAllowed, true)
  assert.equal(after.passkeys.length, 1, 'passkeys are kept')

  await writeFile(join(dir, 'passkeys.json'), '{"v":1}')
  assert.equal((await readPasskeys(dir, secrets.masterKey)).tampered, true, 'a malformed file is distrusted, not a crash')
})
