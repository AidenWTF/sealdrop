import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { MAX_FAILS_GLOBAL, MAX_FAILS_PER_IP, FAIL_WINDOW } from '../src/auth.js'
import { totpCode, verifyTotp, base32Encode } from '../src/crypto.js'
import { loadConfig } from '../src/config.js'
import { PASSWORD, startApp } from './helpers.js'

const sameFailure = async (response) => ({ status: response.status, text: await response.text() })

test('TOTP matches the RFC 6238 test vector', () => {
  const secret = Buffer.from('12345678901234567890')
  assert.equal(totpCode(secret, Math.floor(59 / 30)), '287082')
  assert.equal(totpCode(secret, Math.floor(1111111109 / 30)), '081804')
  assert.equal(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI')
})

test('both factors are required and every failure looks the same', async (t) => {
  const ctx = await startApp(t)
  ctx.clock.ms += 90_000
  const wrongPassword = await sameFailure(await ctx.tryLogin('wrong password here', ctx.currentCode()))
  const wrongCode = await sameFailure(await ctx.tryLogin(PASSWORD, ctx.currentCode() === '000000' ? '000001' : '000000'))
  const noCode = await sameFailure(await ctx.tryLogin(PASSWORD, ''))
  assert.equal(wrongPassword.status, 401)
  assert.deepEqual(wrongPassword, wrongCode)
  assert.deepEqual(wrongPassword, noCode)
})

test('an authenticator code can never be used twice', async (t) => {
  const ctx = await startApp(t)
  ctx.clock.ms += 90_000
  const code = ctx.currentCode()
  assert.equal((await ctx.tryLogin(PASSWORD, code)).status, 303)
  assert.equal((await ctx.tryLogin(PASSWORD, code)).status, 401)
})

test('used codes stay used across a restart', async (t) => {
  const ctx = await startApp(t)
  ctx.clock.ms += 90_000
  const code = ctx.currentCode()
  const clockMs = ctx.clock.ms
  assert.equal((await ctx.tryLogin(PASSWORD, code)).status, 303)
  const restarted = await startApp(t, {}, { dataDir: ctx.dataDir, secrets: ctx.secrets })
  restarted.clock.ms = clockMs
  assert.equal((await restarted.tryLogin(PASSWORD, code)).status, 401)
})

test('codes outside the time window are refused', () => {
  const secret = Buffer.from('12345678901234567890')
  const now = 1_700_000_000_000
  const step = Math.floor(now / 30_000)
  assert.equal(verifyTotp(secret, totpCode(secret, step), now), step)
  assert.equal(verifyTotp(secret, totpCode(secret, step - 1), now), step - 1)
  assert.equal(verifyTotp(secret, totpCode(secret, step + 1), now), step + 1)
  assert.equal(verifyTotp(secret, totpCode(secret, step - 2), now), null)
  assert.equal(verifyTotp(secret, totpCode(secret, step + 2), now), null)
})

test('repeated failures lock out, even with correct details', async (t) => {
  const ctx = await startApp(t)
  ctx.clock.ms += 90_000
  for (let i = 0; i < MAX_FAILS_PER_IP; i++) await ctx.tryLogin('wrong password here', '000000')
  assert.equal((await ctx.tryLogin(PASSWORD, ctx.currentCode())).status, 429)
  ctx.clock.ms += FAIL_WINDOW + 1000
  assert.equal((await ctx.tryLogin(PASSWORD, ctx.currentCode())).status, 303)
})

test('spoofing X-Forwarded-For does not dodge the lockout', async (t) => {
  const direct = await startApp(t)
  for (let i = 0; i < MAX_FAILS_PER_IP; i++) {
    await direct.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': `10.0.0.${i}` })
  }
  assert.equal((await direct.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': '10.9.9.9' })).status, 429)

  // Behind a proxy only the entry it appended counts, not ones the client prepended.
  const proxied = await startApp(t, { TRUST_PROXY: '1' })
  for (let i = 0; i < MAX_FAILS_PER_IP; i++) {
    await proxied.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': `1.2.3.${i}, 203.0.113.9` })
  }
  assert.equal((await proxied.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': '9.9.9.9, 203.0.113.9' })).status, 429)
})

test('a distributed attack hits the global lockout', async (t) => {
  const ctx = await startApp(t, { TRUST_PROXY: '1' })
  ctx.clock.ms += 90_000
  for (let i = 0; i < MAX_FAILS_GLOBAL; i++) {
    await ctx.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': `198.51.100.${i}` })
  }
  const fresh = await ctx.tryLogin(PASSWORD, ctx.currentCode(), { 'X-Forwarded-For': '203.0.113.200' })
  assert.equal(fresh.status, 429)
})

test('the login form can post its origin, while everything else stays no-referrer', async (t) => {
  // Browsers send "Origin: null" on form posts from a no-referrer page, which breaks login.
  const ctx = await startApp(t)
  const login = await fetch(ctx.base)
  assert.equal(login.headers.get('referrer-policy'), 'same-origin')
  assert.ok((await login.text()).includes('<meta name="referrer" content="same-origin">'))
  const failed = await ctx.tryLogin('wrong password here', '000000')
  assert.equal(failed.headers.get('referrer-policy'), 'same-origin')
  assert.ok((await failed.text()).includes('<meta name="referrer" content="same-origin">'))

  const session = await ctx.login()
  const dashboard = await fetch(ctx.base, { headers: { Cookie: session.cookie } })
  assert.equal(dashboard.headers.get('referrer-policy'), 'no-referrer')
  const { pageUrl } = await ctx.upload(session, 'x')
  const share = await fetch(pageUrl)
  assert.equal(share.headers.get('referrer-policy'), 'no-referrer')
  assert.ok((await share.text()).includes('<meta name="referrer" content="no-referrer">'))
})

test('a browser-style "Origin: null" post is still refused', async (t) => {
  const ctx = await startApp(t)
  ctx.clock.ms += 90_000
  assert.equal((await ctx.tryLogin(PASSWORD, ctx.currentCode(), { Origin: 'null' })).status, 403)
})

const signIn = async (ctx, ip, device) => {
  ctx.clock.ms += 90_000
  return ctx.tryLogin(PASSWORD, ctx.currentCode(), { 'X-Forwarded-For': ip, ...(device ? { Cookie: device } : {}) })
}
const deviceCookie = (response) => response.headers.getSetCookie().find((c) => c.includes('_device='))

test('an attacker triggering the global lockout cannot lock out a browser you already use', async (t) => {
  const ctx = await startApp(t, { TRUST_PROXY: '1' })
  const first = await signIn(ctx, '203.0.113.1')
  assert.equal(first.status, 303)
  const issued = deviceCookie(first)
  assert.match(issued, /HttpOnly/)
  assert.match(issued, /SameSite=Strict/)
  const device = issued.split(';')[0]

  for (let i = 0; i < MAX_FAILS_GLOBAL; i++) {
    await ctx.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': `198.51.100.${i}` })
  }
  assert.equal((await signIn(ctx, '203.0.113.50')).status, 429, 'unknown browsers stay locked')
  assert.equal((await signIn(ctx, '203.0.113.1', device)).status, 303, 'a known browser still signs in')
})

test('a trusted browser cookie never replaces the password or code', async (t) => {
  const ctx = await startApp(t, { TRUST_PROXY: '1' })
  const device = deviceCookie(await signIn(ctx, '203.0.113.1')).split(';')[0]
  ctx.clock.ms += 90_000
  assert.equal((await ctx.tryLogin('wrong password here', ctx.currentCode(), { Cookie: device })).status, 401)
  assert.equal((await ctx.tryLogin(PASSWORD, '000000', { Cookie: device })).status, 401)
  assert.equal((await ctx.raw('POST', '/api/upload', { Cookie: device, Origin: ctx.base }, 'x')).status, 401)
  assert.equal((await ctx.raw('GET', '/api/files', { Cookie: device })).status, 401)
  assert.equal(await ctx.storedFiles(), 0)
})

test('a trusted browser has its own attempt limit, so a stolen cookie is not a brute-force path', async (t) => {
  const ctx = await startApp(t, { TRUST_PROXY: '1' })
  const device = deviceCookie(await signIn(ctx, '203.0.113.1')).split(';')[0]
  for (let i = 0; i < MAX_FAILS_PER_IP; i++) {
    await ctx.tryLogin('wrong password here', '000000', { Cookie: device, 'X-Forwarded-For': `192.0.2.${i}` })
  }
  assert.equal((await signIn(ctx, '192.0.2.200', device)).status, 429)
})

test('a forged trusted-browser cookie gets no exemption', async (t) => {
  const ctx = await startApp(t, { TRUST_PROXY: '1' })
  const name = deviceCookie(await signIn(ctx, '203.0.113.1')).split('=')[0]
  for (let i = 0; i < MAX_FAILS_GLOBAL; i++) {
    await ctx.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': `198.51.100.${i}` })
  }
  assert.equal((await signIn(ctx, '203.0.113.60', `${name}=${'A'.repeat(43)}`)).status, 429)
})

test('trusted browsers survive a restart, and only a hash is stored', async (t) => {
  const ctx = await startApp(t, { TRUST_PROXY: '1' })
  const device = deviceCookie(await signIn(ctx, '203.0.113.1')).split(';')[0]
  const stored = await readFile(join(ctx.dataDir, 'devices.json'), 'utf8')
  assert.ok(!stored.includes(device.split('=')[1]), 'the cookie value must not be on disk')

  const restarted = await startApp(t, { TRUST_PROXY: '1' }, { dataDir: ctx.dataDir, secrets: ctx.secrets })
  restarted.clock.ms = ctx.clock.ms
  for (let i = 0; i < MAX_FAILS_GLOBAL; i++) {
    await restarted.tryLogin('wrong password here', '000000', { 'X-Forwarded-For': `198.51.100.${i}` })
  }
  assert.equal((await signIn(restarted, '203.0.113.1', device)).status, 303)
})

test('cross-site login posts are refused', async (t) => {
  const ctx = await startApp(t)
  ctx.clock.ms += 90_000
  assert.equal((await ctx.tryLogin(PASSWORD, ctx.currentCode(), { Origin: 'https://evil.example' })).status, 403)
})

test('session cookie is locked down when served over https', async (t) => {
  const ctx = await startApp(t, { PUBLIC_URL: 'https://files.example.com' })
  const cookie = ctx.app.auth.sessionCookie('value', 1000)
  assert.match(cookie, /^__Host-sealdrop_session=value; Path=\/;/)
  for (const attribute of ['HttpOnly', 'SameSite=Strict', 'Secure']) assert.ok(cookie.includes(attribute), attribute)
})

test('plain http is refused anywhere except localhost', () => {
  assert.throws(() => loadConfig({ PUBLIC_URL: 'http://files.example.com' }), /https/)
  assert.ok(loadConfig({ PUBLIC_URL: 'https://files.example.com' }).secure)
})
