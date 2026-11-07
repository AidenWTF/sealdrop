import assert from 'node:assert/strict'
import { readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileKeys, parseToken } from '../src/crypto.js'
import { startApp } from './helpers.js'

const HOUR = 3600

async function uploadWith(ctx, session, body, headers) {
  return fetch(`${ctx.base}/api/upload`, {
    method: 'POST',
    headers: { ...session.ownerHeaders, 'X-File-Name': 'notes.bin', 'Content-Type': 'application/octet-stream', ...headers },
    body,
  })
}

const bytes = Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.alloc(5000, 9)])

test('a link that expires stops working at its time, and the file is deleted', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const response = await uploadWith(ctx, session, bytes, { 'X-Expires-In': String(HOUR) })
  assert.equal(response.status, 201)
  const file = await response.json()
  assert.equal(file.expiresAt, ctx.clock.ms + HOUR * 1000)
  assert.equal((await fetch(file.pageUrl)).status, 200)

  ctx.clock.ms += HOUR * 1000 - 1
  assert.equal((await fetch(file.rawUrl)).status, 200, 'still fine a moment before')
  ctx.clock.ms += 1
  assert.equal((await fetch(file.pageUrl)).status, 404)
  assert.equal((await fetch(file.rawUrl)).status, 404)
  assert.equal(await ctx.storedFiles(), 0, 'deleted, not just hidden')
})

test('expired files are swept away even if nobody opens them again', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  await (await uploadWith(ctx, session, bytes, { 'X-Expires-In': String(HOUR) })).json()
  const kept = await (await uploadWith(ctx, session, bytes, {})).json()
  ctx.clock.ms += 2 * HOUR * 1000
  await ctx.app.sweep()
  assert.equal(await ctx.storedFiles(), 1)
  const listed = await (await fetch(`${ctx.base}/api/files`, { headers: session.ownerHeaders })).json()
  assert.deepEqual(listed.files.map((f) => f.token), [kept.token])
})

test('a download limit counts whole-file fetches only, and the last one deletes the file', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const file = await (await uploadWith(ctx, session, bytes, { 'X-Max-Downloads': '2' })).json()
  assert.equal(file.maxDownloads, 2)

  assert.equal((await fetch(file.pageUrl)).status, 200, 'viewing the page is free')
  assert.equal((await fetch(file.rawUrl, { method: 'HEAD' })).status, 200, 'HEAD is free')
  assert.equal((await fetch(file.rawUrl, { headers: { Range: 'bytes=100-' } })).status, 206, 'later parts are free')
  const first = await fetch(file.rawUrl)
  assert.ok(Buffer.from(await first.arrayBuffer()).equals(bytes))
  const listed = await (await fetch(`${ctx.base}/api/files`, { headers: session.ownerHeaders })).json()
  assert.equal(listed.files[0].downloads, 1)

  const download = (await fetch(file.pageUrl).then((r) => r.text())).match(/href="(\/download\/[^"]+)"/)[1]
  const last = await fetch(ctx.base + download)
  assert.ok(Buffer.from(await last.arrayBuffer()).equals(bytes), 'the last allowed download is complete')
  assert.equal((await fetch(file.rawUrl)).status, 404)
  assert.equal(await ctx.storedFiles(), 0)
})

test('two downloads at once cannot both be the last one', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const file = await (await uploadWith(ctx, session, bytes, { 'X-Max-Downloads': '1' })).json()
  const results = await Promise.all([fetch(file.rawUrl), fetch(file.rawUrl), fetch(file.rawUrl)])
  const statuses = await Promise.all(results.map(async (r) => { await r.arrayBuffer(); return r.status }))
  assert.deepEqual(statuses.sort(), [200, 404, 404])
})

test('a download count changed on disk ends the link rather than extending it', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const file = await (await uploadWith(ctx, session, bytes, { 'X-Max-Downloads': '5' })).json()
  await fetch(file.rawUrl).then((r) => r.arrayBuffer())
  const dir = join(ctx.dataDir, 'files', fileKeys(parseToken(file.token)).id)
  await writeFile(join(dir, 'downloads'), Buffer.alloc(40))
  assert.equal((await fetch(file.rawUrl)).status, 404)
})

test('only the offered expiry choices and sensible limits are accepted', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  for (const headers of [
    { 'X-Expires-In': '7200' }, { 'X-Expires-In': '-1' }, { 'X-Expires-In': '3600.5' },
    { 'X-Max-Downloads': '0' }, { 'X-Max-Downloads': '1001' }, { 'X-Max-Downloads': 'many' },
  ]) {
    assert.equal((await uploadWith(ctx, session, bytes, headers)).status, 400, JSON.stringify(headers))
  }
  assert.deepEqual(await readdir(join(ctx.dataDir, 'files')), [])
  assert.equal((await uploadWith(ctx, session, bytes, { 'X-Expires-In': String(30 * 86400), 'X-Max-Downloads': '1000' })).status, 201)
})
