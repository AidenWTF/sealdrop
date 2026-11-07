// The most important property of the whole site: nobody but the owner can upload.
import assert from 'node:assert/strict'
import { request } from 'node:http'
import { test } from 'node:test'
import { startApp } from './helpers.js'
import { ABSOLUTE_LIMIT, IDLE_LIMIT } from '../src/auth.js'

const UPLOAD = '/api/upload'
const body = 'attacker data'

async function assertRefused(ctx, attempt, allowed = [401, 403]) {
  const before = await ctx.storedFiles()
  const { status } = await attempt()
  assert.ok(allowed.includes(status) || status === 0, `expected refusal, got ${status}`)
  assert.equal(await ctx.storedFiles(), before, 'nothing may be stored')
  assert.equal(await ctx.tmpEntries(), 0, 'nothing may be left in temp storage')
}

test('anonymous upload is refused and stores nothing', async (t) => {
  const ctx = await startApp(t)
  await assertRefused(ctx, () => ctx.raw('POST', UPLOAD, { Origin: ctx.base }, body))
  assert.ok(ctx.events.some((e) => e.event === 'owner_route_denied' && e.route === 'upload'), 'the attempt must be logged')
})

test('forged, empty and malformed session cookies are refused', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const forged = [
    'sealdrop_session=', 'sealdrop_session=admin', 'sealdrop_session=null',
    `sealdrop_session=${'A'.repeat(43)}`,
    `sealdrop_session=${session.csrf}`, // the CSRF token must not double as a session
    `${session.cookie}x`,
    session.cookie.replace('sealdrop_session', 'other_cookie'),
  ]
  for (const Cookie of forged) {
    await assertRefused(ctx, () => ctx.raw('POST', UPLOAD, { Cookie, Origin: ctx.base, 'X-CSRF-Token': session.csrf }, body))
  }
})

test('a valid session still needs the CSRF token and the right origin', async (t) => {
  const ctx = await startApp(t)
  const { cookie, csrf } = await ctx.login()
  const cases = [
    { Cookie: cookie, Origin: ctx.base },
    { Cookie: cookie, Origin: ctx.base, 'X-CSRF-Token': 'wrong' },
    { Cookie: cookie, Origin: ctx.base, 'X-CSRF-Token': '' },
    { Cookie: cookie, 'X-CSRF-Token': csrf },
    { Cookie: cookie, 'X-CSRF-Token': csrf, Origin: 'https://evil.example' },
    { Cookie: cookie, 'X-CSRF-Token': csrf, Origin: 'null' },
    { Cookie: cookie, 'X-CSRF-Token': csrf, Origin: ctx.base, 'Sec-Fetch-Site': 'cross-site' },
  ]
  for (const headers of cases) await assertRefused(ctx, () => ctx.raw('POST', UPLOAD, headers, body), [403])
})

test('a correctly authenticated owner can upload', async (t) => {
  const ctx = await startApp(t)
  const file = await ctx.upload(await ctx.login(), 'hello', 'note.txt')
  assert.equal(file.name, 'note.txt')
  assert.equal(await ctx.storedFiles(), 1)
})

test('sessions stop working after logout, expiry and restart', async (t) => {
  const ctx = await startApp(t)

  const loggedOut = await ctx.login()
  assert.equal((await ctx.raw('POST', '/logout', loggedOut.ownerHeaders)).status, 204)
  await assertRefused(ctx, () => ctx.raw('POST', UPLOAD, loggedOut.ownerHeaders, body))

  const idle = await ctx.login()
  ctx.clock.ms += IDLE_LIMIT + 1000
  await assertRefused(ctx, () => ctx.raw('POST', UPLOAD, idle.ownerHeaders, body))

  const old = await ctx.login()
  for (let elapsed = 0; elapsed < ABSOLUTE_LIMIT; elapsed += IDLE_LIMIT / 2) {
    ctx.clock.ms += IDLE_LIMIT / 2
    await ctx.raw('GET', '/api/files', { Cookie: old.cookie })
  }
  ctx.clock.ms += 1000
  await assertRefused(ctx, () => ctx.raw('POST', UPLOAD, old.ownerHeaders, body))

  const beforeRestart = await ctx.login()
  const restarted = await startApp(t, {}, { dataDir: ctx.dataDir, secrets: ctx.secrets })
  await assertRefused(restarted, () => restarted.raw('POST', UPLOAD, {
    ...beforeRestart.ownerHeaders, Origin: restarted.base,
  }, body))
})

test('signing out during an upload discards it', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const status = await new Promise((resolve) => {
    const req = request({
      host: '127.0.0.1', port: ctx.port, method: 'POST', path: UPLOAD,
      headers: { ...session.ownerHeaders, 'X-File-Name': 'x', 'Transfer-Encoding': 'chunked' },
    }, (res) => {
      res.resume()
      resolve(res.statusCode)
    })
    req.on('error', () => resolve(0))
    req.write('part one', async () => {
      await new Promise((r) => setTimeout(r, 50))
      await ctx.raw('POST', '/logout', session.ownerHeaders)
      req.end('part two')
    })
  })
  assert.ok(status === 401 || status === 0, `got ${status}`)
  assert.equal(await ctx.storedFiles(), 0)
})

test('path and method tricks do not reach upload without auth', async (t) => {
  const ctx = await startApp(t)
  const attempts = [
    ['POST', '/api/upload/'], ['POST', '//api/upload'], ['POST', '/api//upload'], ['POST', '/API/UPLOAD'],
    ['POST', '/api/upload%2f'], ['POST', '/api/%75pload'], ['POST', '/static/../api/upload'],
    ['POST', '/f/../api/upload'], ['POST', '/api/upload;x=1'], ['PUT', UPLOAD], ['PATCH', UPLOAD],
    ['POST', '/upload'], ['POST', '/'], ['POST', '/register'], ['POST', '/signup'], ['POST', '/setup'],
    ['POST', '/api/users'], ['POST', '/admin'], ['PUT', '/api/files'], ['POST', '/api/files'],
    ['POST', `/file/${'A'.repeat(22)}`], ['PUT', `/raw/${'A'.repeat(22)}/x`], ['POST', `/download/${'A'.repeat(22)}/x`],
  ]
  for (const [method, path] of attempts) {
    await assertRefused(ctx, () => ctx.raw(method, path, { Origin: ctx.base }, body), [401, 403, 404])
  }
  await assertRefused(ctx, () => ctx.raw('POST', '/api/files', { Origin: ctx.base, 'X-HTTP-Method-Override': 'PUT' }, body), [404])
  await assertRefused(ctx, () => ctx.raw('GET', `${UPLOAD}?_method=POST`, { Origin: ctx.base }), [404])
})

test('only login accepts data without a session, and no route can create an owner', async (t) => {
  const ctx = await startApp(t)
  const open = ctx.app.routes.filter((r) => r.access === 'public' && r.methods.some((m) => m !== 'GET' && m !== 'HEAD'))
  assert.deepEqual(open.map((r) => r.path.source), ['^\\/login$'])
  for (const route of ctx.app.routes) {
    if (route.access === 'owner' && !route.methods.includes('GET')) assert.equal(route.csrf, true, route.path.source)
  }
  const upload = ctx.app.routes.find((r) => r.path.source.includes('upload'))
  assert.equal(upload.access, 'owner')
  assert.equal(upload.csrf, true)
})

test('listing and deleting also require the owner', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const { token } = await ctx.upload(session, 'keep me')
  assert.equal((await ctx.raw('GET', '/api/files')).status, 401)
  assert.equal((await ctx.raw('DELETE', `/api/files/${token}`, { Origin: ctx.base })).status, 401)
  assert.equal((await ctx.raw('DELETE', `/api/files/${token}`, { Cookie: session.cookie, Origin: ctx.base })).status, 403)
  assert.equal(await ctx.storedFiles(), 1)
  assert.equal((await ctx.raw('DELETE', `/api/files/${token}`, session.ownerHeaders)).status, 200)
  assert.equal(await ctx.storedFiles(), 0)
})

test('an oversized upload is refused and cleaned up', async (t) => {
  const ctx = await startApp(t, { MAX_UPLOAD_GB: String(1 / 1024 / 1024) }) // 1 KiB
  const session = await ctx.login()
  const declared = await ctx.raw('POST', UPLOAD, { ...session.ownerHeaders, 'Content-Length': 5000 }, Buffer.alloc(5000))
  assert.ok(declared.status === 413 || declared.status === 0, `got ${declared.status}`)
  const undeclared = await ctx.raw('POST', UPLOAD, { ...session.ownerHeaders, 'Transfer-Encoding': 'chunked' }, Buffer.alloc(5000))
  assert.ok(undeclared.status === 413 || undeclared.status === 0, `got ${undeclared.status}`)
  await new Promise((r) => setTimeout(r, 50))
  assert.equal(await ctx.storedFiles(), 0)
  assert.equal(await ctx.tmpEntries(), 0)
})

test('an interrupted upload leaves nothing behind', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  await new Promise((resolve) => {
    const req = request({
      host: '127.0.0.1', port: ctx.port, method: 'POST', path: UPLOAD,
      headers: { ...session.ownerHeaders, 'Content-Length': 1_000_000 },
    })
    req.on('error', resolve)
    req.write('partial', () => setTimeout(() => req.destroy(new Error('gone')), 30))
  })
  await new Promise((r) => setTimeout(r, 80))
  assert.equal(await ctx.storedFiles(), 0)
  assert.equal(await ctx.tmpEntries(), 0)
})

test('read-only requests that declare a body are refused, so they cannot hold connections open', async (t) => {
  const ctx = await startApp(t)
  for (const headers of [{ 'Content-Length': 100_000_000 }, { 'Transfer-Encoding': 'chunked' }]) {
    const status = await new Promise((resolve) => {
      const req = request({ host: '127.0.0.1', port: ctx.port, method: 'GET', path: '/robots.txt', headers }, (res) => {
        res.resume()
        resolve(res.statusCode)
      })
      req.on('error', () => resolve(0))
      req.flushHeaders()
      setTimeout(() => {
        req.destroy()
        resolve('still open')
      }, 500)
    })
    assert.ok(status === 400 || status === 0, `got ${status}`)
  }
  assert.equal((await ctx.raw('GET', '/robots.txt')).status, 200)
})
