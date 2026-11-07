import assert from 'node:assert/strict'
import { test } from 'node:test'
import { newShortCode } from '../src/crypto.js'
import { allDiskFiles, startApp } from './helpers.js'

const json = (session) => ({ ...session.ownerHeaders, 'Content-Type': 'application/json' })
const shorten = (ctx, session, url) => fetch(`${ctx.base}/api/links`, { method: 'POST', headers: json(session), body: JSON.stringify({ url }) })

test('a short link redirects to its address, and only its creator can list or delete it', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const target = 'https://example.com/a/very/long/path?with=query#and-fragment'
  const response = await shorten(ctx, session, target)
  assert.equal(response.status, 201)
  const link = await response.json()
  assert.match(link.code, /^[1-9A-HJ-NP-Za-km-z]{10}$/)
  assert.equal(link.shortUrl, `${ctx.base}/s/${link.code}`)

  const followed = await fetch(link.shortUrl, { redirect: 'manual' })
  assert.equal(followed.status, 302)
  assert.equal(followed.headers.get('location'), target)
  assert.equal(followed.headers.get('referrer-policy'), 'no-referrer')

  const listed = await (await fetch(`${ctx.base}/api/links`, { headers: session.ownerHeaders })).json()
  assert.deepEqual(listed.links.map((l) => [l.code, l.url]), [[link.code, target]])

  for (const { bytes, path } of await allDiskFiles(ctx.dataDir)) {
    assert.ok(!bytes.includes('example.com'), `the address is readable in ${path}`)
    assert.ok(!bytes.includes(link.code), `the code is readable in ${path}`)
  }

  const removed = await fetch(`${ctx.base}/api/links/${link.code}`, { method: 'DELETE', headers: session.ownerHeaders })
  assert.equal(removed.status, 200)
  assert.equal((await fetch(link.shortUrl, { redirect: 'manual' })).status, 404)
})

test('only web addresses are accepted', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  for (const url of ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'ftp://example.com/x', 'not a url', 'https://user:pass@example.com/', `https://example.com/${'a'.repeat(2100)}`, 42]) {
    assert.equal((await shorten(ctx, session, url)).status, 400, String(url).slice(0, 40))
  }
  assert.equal((await fetch(`${ctx.base}/api/links`, { headers: session.ownerHeaders }).then((r) => r.json())).links.length, 0)
})

test('nobody can create short links without signing in, or delete someone else\'s', async (t) => {
  const ctx = await startApp(t)
  const anonymous = await fetch(`${ctx.base}/api/links`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ctx.base }, body: JSON.stringify({ url: 'https://spam.example' }),
  })
  assert.equal(anonymous.status, 401)

  const session = await ctx.login()
  const noCsrf = await fetch(`${ctx.base}/api/links`, {
    method: 'POST', headers: { Cookie: session.cookie, Origin: ctx.base, 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'https://x.example' }),
  })
  assert.equal(noCsrf.status, 403)

  const link = await (await shorten(ctx, session, 'https://kept.example/')).json()
  // A second person with a different master key, as an OIDC member would have.
  const other = ctx.app.auth.createSession({ masterKey: Buffer.alloc(32, 7), member: { id: 'x', name: 'Other' } })
  const csrf = /name="csrf-token" content="([^"]+)"/.exec(await (await fetch(ctx.base, { headers: { Cookie: `sealdrop_session=${other}` } })).text())[1]
  const otherHeaders = { Cookie: `sealdrop_session=${other}`, 'X-CSRF-Token': csrf, Origin: ctx.base }
  assert.equal((await fetch(`${ctx.base}/api/links/${link.code}`, { method: 'DELETE', headers: otherHeaders })).status, 404)
  assert.deepEqual((await (await fetch(`${ctx.base}/api/links`, { headers: otherHeaders })).json()).links, [])
  assert.equal((await fetch(link.shortUrl, { redirect: 'manual' })).status, 302, 'still works')
})

test('guessing short links is cut off after a few misses from one address', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const link = await (await shorten(ctx, session, 'https://real.example/')).json()
  for (let i = 0; i < 30; i++) {
    assert.equal((await fetch(`${ctx.base}/s/${newShortCode()}`, { redirect: 'manual' })).status, 404)
  }
  assert.equal((await fetch(`${ctx.base}/s/${newShortCode()}`, { redirect: 'manual' })).status, 429)
  assert.equal((await fetch(link.shortUrl, { redirect: 'manual' })).status, 429, 'blocked for this address, even for real codes')
  ctx.clock.ms += 15 * 60_000
  assert.equal((await fetch(link.shortUrl, { redirect: 'manual' })).status, 302, 'and free again after the window')
})
