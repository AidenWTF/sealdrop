// Pastes links into a real shell after wget, unquoted, the way a person would.
import assert from 'node:assert/strict'
import { exec, execSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { promisify } from 'node:util'
import { startApp } from './helpers.js'

// Must not block: the server under test runs in this same process.
const shell = promisify(exec)

let available = true
try {
  execSync('wget --version', { stdio: 'ignore' })
} catch {
  available = false
}
const skip = !available && 'wget not available'
const NAMES = [
  'plain.txt', 'with space.txt', 'report (final).txt', "it's.txt", 'a&b=c.txt', 'semi;colon.txt', 'cost $HOME.txt',
  'wild*card?.txt', 'bang!.txt', '~tilde.txt', '100%.txt', 'back`tick`.txt', 'résumé 报告.txt', '#hash.txt', 'no-extension',
]

async function fetchWith(t, command) {
  const dir = await mkdtemp(join(tmpdir(), 'sealdrop-wget-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  await shell(command, { cwd: dir, shell: '/bin/sh', timeout: 20_000 })
  return { dir, saved: await readdir(dir) }
}

test('direct and download links work unquoted with wget and keep the real file name', { skip }, async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  for (const name of NAMES) {
    const body = `contents of ${name}`
    const { token, rawUrl } = await ctx.upload(session, body, name)
    assert.match(rawUrl, /^[A-Za-z0-9:/._%-]+$/, `nothing a shell would interpret: ${rawUrl}`)
    const html = await (await fetch(`${ctx.base}/file/${token}`)).text()
    const download = /class="button primary" href="([^"]+)"/.exec(html)[1]
    assert.ok(!download.includes('?'), 'no query string for wget to add to the file name')

    for (const url of [rawUrl, ctx.base + download]) {
      const { dir, saved } = await fetchWith(t, `wget -q ${url}`)
      assert.deepEqual(saved, [name], url)
      assert.equal(await readFile(join(dir, name), 'utf8'), body, url)
    }
  }
})

test('wget can resume an interrupted download of a large file, across chunks', { skip }, async (t) => {
  const ctx = await startApp(t)
  const content = randomBytes(3 * 1024 * 1024 + 17)
  const { rawUrl } = await ctx.upload(await ctx.login(), content, 'big file.bin')
  const dir = await mkdtemp(join(tmpdir(), 'sealdrop-wget-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  await writeFile(join(dir, 'big file.bin'), content.subarray(0, 1_500_000))
  await shell(`wget -q -c ${rawUrl}`, { cwd: dir, shell: '/bin/sh', timeout: 20_000 })
  assert.equal((await stat(join(dir, 'big file.bin'))).size, content.length)
  assert.ok((await readFile(join(dir, 'big file.bin'))).equals(content))
})

test('wget gets a clear failure for a link that does not exist', { skip }, async (t) => {
  const ctx = await startApp(t)
  const dir = await mkdtemp(join(tmpdir(), 'sealdrop-wget-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  await assert.rejects(shell(`wget -q ${ctx.base}/raw/${'A'.repeat(22)}/x.txt`, { cwd: dir, shell: '/bin/sh', timeout: 20_000 }))
})
