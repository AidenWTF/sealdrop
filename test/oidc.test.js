import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { test } from 'node:test'
import { loadConfig } from '../src/config.js'
import { startApp } from './helpers.js'

const ISSUER = 'https://id.example.test'
const CLIENT_ID = 'sealdrop'
const CLIENT_SECRET = 'test-client-secret'
const b64 = (value) => Buffer.from(value).toString('base64url')

// A stand-in for Pocket ID: discovery, keys, and a token endpoint that checks PKCE and the
// client secret. `misbehave` makes it hand out a bad token in one particular way.
function fakeProvider() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const stranger = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' }
  const codes = new Map()
  const provider = { misbehave: null, users: {}, tokenRequests: 0 }

  provider.authorize = (location, user) => {
    const url = new URL(location)
    assert.equal(url.origin + url.pathname, `${ISSUER}/authorize`)
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
    assert.match(url.searchParams.get('scope'), /groups/)
    const code = b64(randomBytes(16))
    codes.set(code, { user, nonce: url.searchParams.get('nonce'), challenge: url.searchParams.get('code_challenge') })
    return { code, state: url.searchParams.get('state') }
  }

  function idToken({ user, nonce }) {
    const now = Math.floor(Date.now() / 1000)
    const claims = { iss: ISSUER, aud: CLIENT_ID, sub: user.sub, name: user.name, groups: user.groups, nonce, iat: now, exp: now + 300 }
    const bad = provider.misbehave
    if (bad === 'audience') claims.aud = 'someone-else'
    if (bad === 'issuer') claims.iss = 'https://evil.example'
    if (bad === 'nonce') claims.nonce = 'wrong'
    if (bad === 'expired') claims.exp = now - 3600
    const header = { alg: bad === 'none' ? 'none' : 'RS256', kid: 'k1', typ: 'JWT' }
    const body = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(claims))}`
    if (bad === 'none') return `${body}.`
    return `${body}.${b64(sign('sha256', Buffer.from(body), bad === 'signature' ? stranger : privateKey))}`
  }

  provider.fetch = async (url, options = {}) => {
    const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return json({
        issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/api/oidc/token`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`, token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      })
    }
    if (url === `${ISSUER}/.well-known/jwks.json`) return json({ keys: [jwk] })
    if (url === `${ISSUER}/api/oidc/token`) {
      provider.tokenRequests++
      const body = new URLSearchParams(options.body)
      assert.equal(options.headers.Authorization, `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`)
      const issued = codes.get(body.get('code'))
      codes.delete(body.get('code'))
      if (!issued) return json({ error: 'invalid_grant' }, 400)
      const challenge = createHash('sha256').update(body.get('code_verifier')).digest('base64url')
      if (challenge !== issued.challenge) return json({ error: 'invalid_grant' }, 400)
      return json({ access_token: 'x', token_type: 'Bearer', id_token: idToken(issued) })
    }
    throw new Error(`unexpected fetch ${url}`)
  }
  return provider
}

const OIDC_ENV = {
  OIDC_ISSUER: ISSUER, OIDC_CLIENT_ID: CLIENT_ID, OIDC_CLIENT_SECRET: CLIENT_SECRET,
  OIDC_NAME: 'Pocket ID', MEMBER_KEY: randomBytes(32).toString('base64'),
}

async function oidcApp(t, env = {}, existing = null) {
  const provider = fakeProvider()
  const ctx = await startApp(t, { ...OIDC_ENV, ...env }, existing, { oidcFetch: provider.fetch })
  return { ctx, provider }
}

// The whole round trip a browser makes. Returns the callback response and its cookies.
async function signIn(ctx, provider, user, tamper = (step) => step) {
  const start = await fetch(`${ctx.base}/oidc/login`, { redirect: 'manual' })
  assert.equal(start.status, 303)
  const browser = start.headers.getSetCookie().find((c) => c.startsWith('sealdrop_oidc=')).split(';')[0]
  const step = tamper({ ...provider.authorize(start.headers.get('location'), user), browser })
  const callback = await fetch(`${ctx.base}/oidc/callback?${new URLSearchParams({ code: step.code, state: step.state })}`, {
    redirect: 'manual', headers: step.browser ? { Cookie: step.browser } : {},
  })
  const session = callback.headers.getSetCookie().find((c) => c.includes('_session='))?.split(';')[0] ?? null
  return { callback, session, html: await callback.text() }
}

const alice = { sub: 'user-alice', name: 'Alice', groups: ['family'] }
const bob = { sub: 'user-bob', name: 'Bob', groups: ['friends'] }

async function dashboard(ctx, cookie) {
  const html = await (await fetch(ctx.base, { headers: { Cookie: cookie } })).text()
  return { html, csrf: /name="csrf-token" content="([^"]+)"/.exec(html)?.[1] }
}

test('people at the provider sign in, get their own files, and nothing of anyone else', async (t) => {
  const { ctx, provider } = await oidcApp(t)
  const login = await (await fetch(ctx.base)).text()
  assert.ok(login.includes('<a class="button sso" href="/oidc/login">Sign in with Pocket ID</a>'))

  const first = await signIn(ctx, provider, alice)
  assert.equal(first.callback.status, 200)
  assert.match(first.html, /http-equiv="refresh" content="0;url=\/"/)
  assert.ok(first.session)
  const { html, csrf } = await dashboard(ctx, first.session)
  assert.match(html, /<span class="muted small">Alice<\/span>/)
  assert.ok(!html.includes('id="security"'), 'no owner settings for members')
  const aliceHeaders = { Cookie: first.session, 'X-CSRF-Token': csrf, Origin: ctx.base }

  const upload = (headers, body, name) => fetch(`${ctx.base}/api/upload`, { method: 'POST', headers: { ...headers, 'X-File-Name': name }, body }).then((r) => r.json())
  const aliceFile = await upload(aliceHeaders, Buffer.from([0, 1, 2, 3]), 'alice.bin')
  const owner = await ctx.login()
  const ownerFile = await upload(owner.ownerHeaders, Buffer.from([4, 5, 6, 7]), 'owner.bin')
  const list = async (headers) => (await (await fetch(`${ctx.base}/api/files`, { headers })).json()).files.map((f) => f.name)
  assert.deepEqual(await list(aliceHeaders), ['alice.bin'])
  assert.deepEqual(await list(owner.ownerHeaders), ['owner.bin'])

  assert.equal((await fetch(`${ctx.base}/api/files/${ownerFile.token}`, { method: 'DELETE', headers: aliceHeaders })).status, 404, "can't delete another person's file")
  assert.equal((await fetch(ownerFile.rawUrl)).status, 200)
  assert.equal((await fetch(`${ctx.base}/api/passkeys`, { headers: aliceHeaders })).status, 403, "the owner's settings are off limits")
  assert.equal((await fetch(`${ctx.base}/api/files/${aliceFile.token}`, { method: 'DELETE', headers: aliceHeaders })).status, 200)

  // Signing in again gives the same key, so the same list.
  const kept = await upload(aliceHeaders, Buffer.from([8, 9]), 'kept.bin')
  const again = await signIn(ctx, provider, alice)
  const second = await dashboard(ctx, again.session)
  assert.deepEqual(await list({ Cookie: again.session, 'X-CSRF-Token': second.csrf, Origin: ctx.base }), [kept.name])

  const bobIn = await signIn(ctx, provider, bob)
  const bobDash = await dashboard(ctx, bobIn.session)
  assert.deepEqual(await list({ Cookie: bobIn.session, 'X-CSRF-Token': bobDash.csrf }), [], 'Bob sees nothing of Alice')
  assert.ok(ctx.events.some((e) => e.event === 'login_ok' && e.method === 'oidc'))
})

test('every bad answer from the provider, or a swapped browser, is refused', async (t) => {
  const { ctx, provider } = await oidcApp(t)
  for (const bad of ['signature', 'audience', 'issuer', 'nonce', 'expired', 'none']) {
    provider.misbehave = bad
    const result = await signIn(ctx, provider, alice)
    assert.equal(result.callback.status, 403, bad)
    assert.equal(result.session, null, bad)
  }
  provider.misbehave = null

  const otherBrowser = await signIn(ctx, provider, alice, (step) => ({ ...step, browser: 'sealdrop_oidc=someone-elses' }))
  assert.equal(otherBrowser.callback.status, 403, 'login CSRF: the answer must come back to the browser that asked')
  const noCookie = await signIn(ctx, provider, alice, (step) => ({ ...step, browser: null }))
  assert.equal(noCookie.callback.status, 403)
  const madeUp = await signIn(ctx, provider, alice, (step) => ({ ...step, state: 'not-issued' }))
  assert.equal(madeUp.callback.status, 403)

  const ok = await signIn(ctx, provider, alice)
  assert.equal(ok.callback.status, 200)
  const replay = await fetch(`${ctx.base}/oidc/callback?error=access_denied&state=x`, { redirect: 'manual' })
  assert.equal(replay.status, 403)
  assert.ok(ctx.events.filter((e) => e.event === 'oidc_refused').length >= 9)
})

test('an allowed group, when set, keeps everyone else out', async (t) => {
  const { ctx, provider } = await oidcApp(t, { OIDC_ALLOWED_GROUP: 'family' })
  assert.ok((await signIn(ctx, provider, alice)).session)
  const refused = await signIn(ctx, provider, bob)
  assert.equal(refused.callback.status, 403)
  assert.equal(refused.session, null)
  assert.match(refused.html, /Your account is not allowed to use this site/)
})

test('without OIDC settings there is no button and no route', async (t) => {
  const ctx = await startApp(t)
  assert.ok(!(await (await fetch(ctx.base)).text()).includes('/oidc/login'))
  assert.equal((await fetch(`${ctx.base}/oidc/login`, { redirect: 'manual' })).status, 404)
  assert.equal((await fetch(`${ctx.base}/oidc/callback?code=x&state=y`, { redirect: 'manual' })).status, 404)
})

test('OIDC settings are checked when the server starts', () => {
  const base = { OIDC_ISSUER: ISSUER, OIDC_CLIENT_ID: CLIENT_ID }
  assert.throws(() => loadConfig(base), /MEMBER_KEY/)
  assert.throws(() => loadConfig({ ...base, MEMBER_KEY: Buffer.alloc(16).toString('base64') }), /MEMBER_KEY/)
  assert.throws(() => loadConfig({ ...base, OIDC_ISSUER: 'http://id.example.com', MEMBER_KEY: OIDC_ENV.MEMBER_KEY }), /https/)
  assert.throws(() => loadConfig({ OIDC_ISSUER: ISSUER, MEMBER_KEY: OIDC_ENV.MEMBER_KEY }), /CLIENT_ID/)
  assert.ok(loadConfig({ ...base, MEMBER_KEY: OIDC_ENV.MEMBER_KEY }).oidc)
})
