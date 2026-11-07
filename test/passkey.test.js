import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { FAIL_WINDOW } from '../src/auth.js'
import { decodeCbor, verifyRegistration } from '../src/webauthn.js'
import { PASSWORD, startApp } from './helpers.js'

const sha256 = (data) => createHash('sha256').update(data).digest()
const b64 = (buffer) => Buffer.from(buffer).toString('base64url')

function cbor(value) {
  const head = (major, n) => {
    if (n < 24) return Buffer.from([(major << 5) | n])
    if (n < 256) return Buffer.from([(major << 5) | 24, n])
    if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255])
    const b = Buffer.alloc(5)
    b[0] = (major << 5) | 26
    b.writeUInt32BE(n, 1)
    return b
  }
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value])
  if (typeof value === 'string') return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)])
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)])
  const entries = value instanceof Map ? [...value] : Object.entries(value)
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])])
}

// Signs exactly like a phone or password manager would, with a real P-256 key.
class SoftPasskey {
  constructor(rpId, { counting = true } = {}) {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    this.privateKey = privateKey
    this.jwk = publicKey.export({ format: 'jwk' })
    this.rawId = randomBytes(32)
    this.id = b64(this.rawId)
    this.rpId = rpId
    this.counting = counting
    this.count = 0
  }

  #authData(attested, count) {
    const flags = 0x01 | 0x04 | (attested ? 0x40 : 0)
    const counter = Buffer.alloc(4)
    counter.writeUInt32BE(count)
    const parts = [sha256(this.rpId), Buffer.from([flags]), counter]
    if (attested) {
      const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(this.jwk.x, 'base64url')], [-3, Buffer.from(this.jwk.y, 'base64url')]])
      const length = Buffer.alloc(2)
      length.writeUInt16BE(this.rawId.length)
      parts.push(Buffer.alloc(16), length, this.rawId, cbor(cose))
    }
    return Buffer.concat(parts)
  }

  register(challenge, origin) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin }))
    const attestationObject = cbor({ fmt: 'none', attStmt: {}, authData: this.#authData(true, 0) })
    return { clientDataJSON: b64(clientDataJSON), attestationObject: b64(attestationObject) }
  }

  assert(challenge, origin, { count } = {}) {
    if (this.counting) this.count++
    const authenticatorData = this.#authData(false, count ?? (this.counting ? this.count : 0))
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }))
    const signature = sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), this.privateKey)
    return { id: this.id, clientDataJSON: b64(clientDataJSON), authenticatorData: b64(authenticatorData), signature: b64(signature) }
  }
}

async function setup(t) {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const json = { ...session.ownerHeaders, 'Content-Type': 'application/json' }
  const options = await (await fetch(`${ctx.base}/api/passkeys/options`, { method: 'POST', headers: session.ownerHeaders })).json()
  const passkey = new SoftPasskey(options.rp.id)
  const added = await fetch(`${ctx.base}/api/passkeys`, {
    method: 'POST', headers: json, body: JSON.stringify({ name: 'Laptop', response: passkey.register(options.challenge, ctx.base) }),
  })
  assert.equal(added.status, 201)
  return { ctx, session, json, options, passkey }
}

async function challenge(ctx) {
  return (await (await fetch(`${ctx.base}/login/challenge`)).json()).challenge
}

function postLogin(ctx, fields) {
  return fetch(`${ctx.base}/login`, {
    method: 'POST', redirect: 'manual',
    headers: { Origin: ctx.base, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
  })
}

const passkeyLogin = (ctx, assertion, password = PASSWORD) => postLogin(ctx, { password, passkey: JSON.stringify(assertion) })

test('a passkey added from the dashboard signs in together with the password', async (t) => {
  const { ctx, session, options, passkey } = await setup(t)
  assert.equal(options.rp.id, '127.0.0.1')
  assert.equal(options.authenticatorSelection.residentKey, 'required')
  assert.equal(options.attestation, 'none')

  const listed = await (await fetch(`${ctx.base}/api/passkeys`, { headers: session.ownerHeaders })).json()
  assert.equal(listed.passkeys.length, 1)
  assert.equal(listed.passkeys[0].name, 'Laptop')
  assert.equal(listed.codesAllowed, true)

  const response = await passkeyLogin(ctx, passkey.assert(await challenge(ctx), ctx.base))
  assert.equal(response.status, 303)
  const cookie = response.headers.getSetCookie().find((c) => c.includes('_session=')).split(';')[0]
  assert.equal((await fetch(`${ctx.base}/api/files`, { headers: { Cookie: cookie } })).status, 200)
  assert.ok(ctx.events.some((e) => e.event === 'login_ok' && e.method === 'passkey'))

  const page = await (await fetch(ctx.base)).text()
  assert.match(page, /data-passkeys="yes"/)
  assert.match(page, /<script src="\/static\/login.js" defer>/)
})

test('every way a passkey sign-in can be wrong is refused the same way', async (t) => {
  const { ctx, passkey } = await setup(t)
  const stranger = new SoftPasskey('127.0.0.1')

  assert.equal((await passkeyLogin(ctx, passkey.assert(await challenge(ctx), ctx.base), 'not the password')).status, 401)
  const used = passkey.assert(await challenge(ctx), ctx.base)
  assert.equal((await passkeyLogin(ctx, used)).status, 303)
  assert.equal((await passkeyLogin(ctx, used)).status, 401, 'a challenge works once')
  assert.equal((await passkeyLogin(ctx, passkey.assert(await challenge(ctx), 'https://evil.example'))).status, 401, 'phishing origin')
  assert.equal((await passkeyLogin(ctx, stranger.assert(await challenge(ctx), ctx.base))).status, 401, 'unknown passkey')

  ctx.clock.ms += FAIL_WINDOW
  assert.equal((await passkeyLogin(ctx, passkey.assert(b64(randomBytes(32)), ctx.base))).status, 401, 'a challenge never issued')
  assert.equal((await passkeyLogin(ctx, passkey.assert(await challenge(ctx), ctx.base, { count: 1 }))).status, 401, 'counter went backwards')
  const tampered = passkey.assert(await challenge(ctx), ctx.base)
  tampered.signature = b64(Buffer.from(tampered.signature, 'base64url').reverse())
  assert.equal((await passkeyLogin(ctx, tampered)).status, 401, 'bad signature')
  assert.equal((await postLogin(ctx, { password: PASSWORD, passkey: '{not json' })).status, 401)

  ctx.clock.ms += FAIL_WINDOW
  const late = await challenge(ctx)
  ctx.clock.ms += 6 * 60_000
  assert.equal((await passkeyLogin(ctx, passkey.assert(late, ctx.base))).status, 401, 'an expired challenge')
})

test('codes can be turned off once a passkey exists, and come back when the last one goes', async (t) => {
  const { ctx, session, json, passkey } = await setup(t)
  const codes = (allowed) => fetch(`${ctx.base}/api/settings/codes`, { method: 'POST', headers: json, body: JSON.stringify({ allowed }) })

  const off = await codes(false)
  assert.equal(off.status, 200)
  assert.equal((await off.json()).codesAllowed, false)
  ctx.clock.ms += 90_000
  assert.equal((await ctx.tryLogin(PASSWORD, ctx.currentCode())).status, 401, 'a correct code no longer works')
  assert.equal((await passkeyLogin(ctx, passkey.assert(await challenge(ctx), ctx.base))).status, 303)
  const page = await (await fetch(ctx.base)).text()
  assert.ok(!page.includes('name="code"'), 'the login page offers no code field')

  const removed = await fetch(`${ctx.base}/api/passkeys/${passkey.id}`, { method: 'DELETE', headers: session.ownerHeaders })
  assert.equal(removed.status, 200)
  assert.deepEqual(await removed.json(), { codesAllowed: true, passkeys: [] })
  assert.equal((await codes(false)).status, 409, 'not without a passkey')
  ctx.clock.ms += 90_000
  assert.equal((await ctx.tryLogin(PASSWORD, ctx.currentCode())).status, 303)
})

test('a passkey list changed on disk is ignored, and codes still let the owner in', async (t) => {
  const { ctx, passkey } = await setup(t)
  const path = join(ctx.dataDir, 'passkeys.json')
  const stored = JSON.parse(await readFile(path, 'utf8'))
  const attacker = new SoftPasskey('127.0.0.1')
  const options = { challenge: b64(randomBytes(32)) }
  const record = verifyRegistration(attacker.register(options.challenge, ctx.base), {
    challenge: Buffer.from(options.challenge, 'base64url'), origin: ctx.base, rpId: '127.0.0.1',
  })
  stored.body.passkeys.push({ ...record, name: 'attacker', createdAt: 0, lastUsedAt: null })
  stored.body.codesAllowed = false
  await writeFile(path, JSON.stringify(stored))

  assert.equal((await passkeyLogin(ctx, attacker.assert(await challenge(ctx), ctx.base))).status, 401)
  assert.equal((await passkeyLogin(ctx, passkey.assert(await challenge(ctx), ctx.base))).status, 401, 'the whole list is distrusted')
  ctx.clock.ms += 90_000
  assert.equal((await ctx.tryLogin(PASSWORD, ctx.currentCode())).status, 303, 'codes work again')
  assert.ok(ctx.events.some((e) => e.event === 'passkeys_tampered'))
})

test('registration only accepts an answer to its own fresh challenge from this site', async (t) => {
  const { ctx, session, json } = await setup(t)
  const add = (body) => fetch(`${ctx.base}/api/passkeys`, { method: 'POST', headers: json, body: JSON.stringify(body) })
  const fresh = new SoftPasskey('127.0.0.1')
  assert.equal((await add({ name: 'x', response: fresh.register(b64(randomBytes(32)), ctx.base) })).status, 400, 'no options asked for')

  const options = await (await fetch(`${ctx.base}/api/passkeys/options`, { method: 'POST', headers: session.ownerHeaders })).json()
  assert.equal(options.excludeCredentials.length, 1, 'existing passkeys are excluded')
  assert.equal((await add({ name: 'x', response: fresh.register(options.challenge, 'https://evil.example') })).status, 400)
  const again = await (await fetch(`${ctx.base}/api/passkeys/options`, { method: 'POST', headers: session.ownerHeaders })).json()
  const otherSite = new SoftPasskey('evil.example')
  assert.equal((await add({ name: 'x', response: otherSite.register(again.challenge, ctx.base) })).status, 400)

  const noCsrf = await fetch(`${ctx.base}/api/passkeys/options`, { method: 'POST', headers: { Cookie: session.cookie, Origin: ctx.base } })
  assert.equal(noCsrf.status, 403)
})

test('the CBOR reader refuses malformed and hostile input', () => {
  assert.deepEqual(decodeCbor(cbor({ a: [1, -2, Buffer.from('hi')] }))[0], new Map([['a', [1, -2, Buffer.from('hi')]]]))
  assert.throws(() => decodeCbor(Buffer.from([0x5a, 0xff, 0xff, 0xff, 0xff])), /truncated/)
  assert.throws(() => decodeCbor(Buffer.alloc(40, 0x81)), /too deep/)
  assert.throws(() => decodeCbor(Buffer.from([0x9f])), /indefinite/)
  assert.throws(() => decodeCbor(Buffer.from([0xc1, 0x00])), /tags/)
})
