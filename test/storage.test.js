import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { readFile, writeFile, readdir, rm, truncate } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { CHUNK_SIZE, TAG_SIZE, fileKeys, newToken, parseToken } from '../src/crypto.js'
import { PASSWORD, allDiskFiles, startApp } from './helpers.js'

const MB = 1024 * 1024
const tokenOf = (url) => /\/file\/([1-9A-HJ-NP-Za-km-z]{22})\//.exec(url)[1]
const dataPath = async (ctx) => {
  const [id] = await readdir(join(ctx.dataDir, 'files'))
  return join(ctx.dataDir, 'files', id, 'data')
}

test('nothing readable is left on disk: no contents, names, links or keys', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const marker = 'TOP-SECRET-CONTENT-MARKER'
  const name = 'my-very-private-holiday.txt'
  const file = await ctx.upload(session, marker.repeat(100000), name)
  const token = tokenOf(file.pageUrl)
  const keys = fileKeys(parseToken(token))
  const md5 = createHash('md5').update(marker.repeat(100000))

  const disk = await allDiskFiles(ctx.dataDir)
  assert.ok(disk.length >= 3)
  const needles = [marker, name, token, PASSWORD, md5.copy().digest('hex'), md5.digest(), ...[keys.data, keys.meta, keys.thumb, ctx.secrets.masterKey, ctx.secrets.totpSecret].flatMap(
    (key) => [key, key.toString('base64'), key.toString('hex'), key.toString('base64url')],
  )]
  for (const { path, bytes } of disk) {
    for (const needle of needles) assert.ok(!bytes.includes(needle), `found a secret in ${path}`)
  }
  for (const { mode, path } of disk) assert.equal(mode & 0o077, 0, `${path} is readable by others`)
  assert.equal(await ctx.tmpEntries(), 0)

  // The audit log carries no secrets either.
  const logged = JSON.stringify(ctx.events)
  for (const needle of [token, name, PASSWORD, session.cookie]) assert.ok(!logged.includes(needle))
})

test('round trip is byte-exact across sizes and chunk boundaries', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  for (const size of [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 2, 3 * MB + 17]) {
    const content = randomBytes(size)
    const file = await ctx.upload(session, content)
    const response = await fetch(file.rawUrl)
    assert.equal(response.status, 200)
    assert.equal(Number(response.headers.get('content-length')), size)
    assert.ok(Buffer.from(await response.arrayBuffer()).equals(content), `size ${size}`)
  }
})

test('range requests return exactly the requested bytes', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const content = randomBytes(3 * MB + 17)
  const { rawUrl } = await ctx.upload(session, content)
  const size = content.length
  const cases = [
    ['bytes=0-0', 0, 0], ['bytes=0-99', 0, 99], [`bytes=${CHUNK_SIZE - 5}-${CHUNK_SIZE + 5}`, CHUNK_SIZE - 5, CHUNK_SIZE + 5],
    [`bytes=${CHUNK_SIZE}-${CHUNK_SIZE}`, CHUNK_SIZE, CHUNK_SIZE], [`bytes=${size - 10}-`, size - 10, size - 1],
    ['bytes=-10', size - 10, size - 1], [`bytes=100-${size + 999}`, 100, size - 1], [`bytes=-${size + 5}`, 0, size - 1],
  ]
  for (const [Range, start, end] of cases) {
    const response = await fetch(rawUrl, { headers: { Range } })
    assert.equal(response.status, 206, Range)
    assert.equal(response.headers.get('content-range'), `bytes ${start}-${end}/${size}`)
    assert.ok(Buffer.from(await response.arrayBuffer()).equals(content.subarray(start, end + 1)), Range)
  }
  for (const Range of [`bytes=${size}-`, `bytes=${size + 1}-${size + 2}`, 'bytes=-0', 'bytes=5-2']) {
    const response = await fetch(rawUrl, { headers: { Range } })
    assert.equal(response.status, 416, Range)
    assert.equal(response.headers.get('content-range'), `bytes */${size}`)
  }
  const head = await fetch(rawUrl, { method: 'HEAD' })
  assert.equal(Number(head.headers.get('content-length')), size)
  assert.equal(head.headers.get('accept-ranges'), 'bytes')
})

async function assertUnreadable(url, expected) {
  let delivered = null
  try {
    delivered = Buffer.from(await (await fetch(url)).arrayBuffer())
  } catch {
    return
  }
  assert.ok(!delivered.equals(expected), 'tampered data must not be delivered as complete')
  assert.ok(delivered.length < expected.length)
}

test('tampering with stored data is detected', async (t) => {
  const content = randomBytes(3 * MB)

  await t.test('a flipped bit', async (t) => {
    const ctx = await startApp(t)
    const { rawUrl } = await ctx.upload(await ctx.login(), content)
    const path = await dataPath(ctx)
    const bytes = await readFile(path)
    bytes[CHUNK_SIZE + 100] ^= 1
    await writeFile(path, bytes)
    await assertUnreadable(rawUrl, content)
    assert.ok(ctx.events.some((e) => e.event === 'integrity_failure'))
  })

  await t.test('reordered chunks', async (t) => {
    const ctx = await startApp(t)
    const { rawUrl } = await ctx.upload(await ctx.login(), content)
    const path = await dataPath(ctx)
    const bytes = await readFile(path)
    const unit = CHUNK_SIZE + TAG_SIZE
    await writeFile(path, Buffer.concat([bytes.subarray(unit, 2 * unit), bytes.subarray(0, unit), bytes.subarray(2 * unit)]))
    await assertUnreadable(rawUrl, content)
  })

  await t.test('a truncated file', async (t) => {
    const ctx = await startApp(t)
    const { rawUrl } = await ctx.upload(await ctx.login(), content)
    await truncate(await dataPath(ctx), 2 * (CHUNK_SIZE + TAG_SIZE))
    await assertUnreadable(rawUrl, content)
  })

  await t.test('altered metadata makes the file unavailable', async (t) => {
    const ctx = await startApp(t)
    const { pageUrl } = await ctx.upload(await ctx.login(), 'small')
    const path = join(await dataPath(ctx), '..', 'meta')
    const bytes = await readFile(path)
    bytes[bytes.length - 1] ^= 1
    await writeFile(path, bytes)
    assert.equal((await fetch(pageUrl)).status, 404)
  })
})

test('a link cannot be guessed or derived', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const { token, pageUrl } = await ctx.upload(session, 'private')
  assert.equal(parseToken(token).length, 16, '128 bits of randomness')
  assert.equal((await fetch(pageUrl)).status, 200)

  const flipped = (token[0] === 'A' ? 'B' : 'A') + token.slice(1)
  const [id] = await readdir(join(ctx.dataDir, 'files'))
  const attempts = [
    `/file/${flipped}`, `/file/${token.slice(0, -1)}`, `/file/${token}x`, `/file/${id}`, `/raw/${id}/x`,
    `/raw/${flipped}/x`, `/download/${flipped}/x`, `/thumb/${flipped}.jpg`,
    `/file/..%2f..%2fowner.json`, `/file/../../owner.json`, `/file/%2e%2e/owner.json`, '/file/', '/file',
    `/raw/${token}/../../owner.json/x`, `/f/${token}`,
    '/data/owner.json', '/owner.json', '/.env', '/files', '/static/../../owner.json', '/static/server.js',
  ]
  for (const path of attempts) {
    const response = await ctx.raw('GET', path)
    assert.equal(response.status, 404, path)
    assert.ok(!response.body.includes('vault'), path)
  }
})

test('tokens are random, unambiguous and strictly validated', () => {
  const seen = new Set()
  for (let i = 0; i < 2000; i++) {
    const token = newToken()
    assert.match(token, /^[1-9A-HJ-NP-Za-km-z]{22}$/, 'no look-alike characters or symbols')
    assert.equal(parseToken(token).length, 16)
    seen.add(token)
  }
  assert.equal(seen.size, 2000)

  // Different tokens must never decode to the same key material.
  assert.ok(parseToken('1'.repeat(22)).equals(Buffer.alloc(16)))
  assert.ok(!parseToken('1'.repeat(21) + '2').equals(Buffer.alloc(16)))
  const rejected = [
    'z'.repeat(22), // more than 128 bits
    '1'.repeat(21), '1'.repeat(23), '', '0'.repeat(22), 'O'.repeat(22), 'I'.repeat(22), 'l'.repeat(22),
    `${'1'.repeat(21)}-`, `${'1'.repeat(21)}_`, `${'1'.repeat(21)}\n`, null, undefined, 123,
  ]
  for (const token of rejected) assert.equal(parseToken(token), null, String(token))
})

test('a deleted link looks the same as one that never existed', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const { token, pageUrl, rawUrl } = await ctx.upload(session, 'soon gone')
  await ctx.raw('DELETE', `/api/files/${token}`, session.ownerHeaders)
  const deleted = await fetch(pageUrl)
  const neverExisted = await fetch(`${ctx.base}/file/${'A'.repeat(22)}`)
  assert.equal(deleted.status, 404)
  assert.equal(await deleted.text(), await neverExisted.text())
  assert.equal((await fetch(rawUrl)).status, 404)
})

test('the dashboard lists only files the master key can open', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const kept = await ctx.upload(session, 'one', 'one.txt')
  await ctx.upload(session, 'two', 'two.txt')
  const dirs = await readdir(join(ctx.dataDir, 'files'))
  for (const id of dirs) {
    if (id !== fileKeys(parseToken(kept.token)).id) await rm(join(ctx.dataDir, 'files', id, 'owner'))
  }
  const { files } = await (await fetch(`${ctx.base}/api/files`, { headers: { Cookie: session.cookie } })).json()
  assert.deepEqual(files.map((f) => f.name), ['one.txt'])
})
