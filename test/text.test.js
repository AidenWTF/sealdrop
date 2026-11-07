import assert from 'node:assert/strict'
import { test } from 'node:test'
import { startApp } from './helpers.js'

const meta = (html, key) => new RegExp(`<meta (?:property|name)="${key}" content="([^"]*)"`).exec(html)?.[1]
const DISCORD = { 'User-Agent': 'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)' }

test('Markdown is rendered, with its HTML shown as text and only safe links', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const source = [
    '# Release notes',
    '',
    'Some **bold** text and `code`.',
    '',
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '',
    '[bad](javascript:alert(1)) [good](https://example.com/page) [mail](mailto:a@example.com) [local](/api/files)',
    '![pic](https://tracker.example/p.png)',
    '',
    '```python',
    'def hi():',
    '    return "<b>"',
    '```',
  ].join('\n')
  const file = await ctx.upload(session, source, 'README.md')
  assert.equal(file.kind, 'text')

  const html = await (await fetch(file.pageUrl)).text()
  assert.match(html, /<article class="markdown">/)
  assert.match(html, /<h1>Release notes<\/h1>/)
  assert.match(html, /<strong>bold<\/strong>/)
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'raw HTML is shown as text')
  assert.ok(!html.includes('<script>alert') && !/<img[^>]*onerror/i.test(html))
  assert.ok(!/href="javascript/i.test(html), 'script links are dropped')
  assert.ok(!html.includes('<a href="javascript'), 'script links are dropped')
  assert.ok(html.includes('<a href="https://example.com/page" rel="nofollow noopener noreferrer ugc">good</a>'))
  assert.ok(html.includes('href="mailto:a@example.com"'))
  assert.ok(!html.includes('href="/api/files"'), 'relative links would point into this site')
  assert.ok(!/<img[^>]*tracker/.test(html), 'outside images become links, not loads')
  assert.match(html, /<span class="hljs-keyword">def<\/span>/, 'fenced code is highlighted')
  assert.ok(html.includes('&quot;&lt;b&gt;&quot;'))

  const sourceView = await (await fetch(`${file.pageUrl}?view=source`)).text()
  assert.ok(!sourceView.includes('<article class="markdown">'))
  assert.match(sourceView, /<pre class="code"><code class="hljs"><span class="line">/)
  assert.equal((sourceView.match(/<span class="line">/g) ?? []).length, 14, 'one numbered line per source line')
})

test('code is highlighted by its extension, with every line standing alone', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const code = 'const greeting = "hi" /* a comment\nthat spans lines */\nfunction f() { return 42 }\n'
  const file = await ctx.upload(session, code, 'app.js')
  const html = await (await fetch(file.pageUrl, { headers: DISCORD })).text()
  assert.match(html, /<span class="text-lang">JavaScript<\/span>/)
  assert.match(html, /3 lines/)
  const lines = [...html.matchAll(/<span class="line">(.*?)<\/span>(?=<span class="line">|<\/code>)/g)].map((m) => m[1])
  assert.equal(lines.length, 3)
  for (const line of lines) {
    assert.equal((line.match(/<span/g) ?? []).length, (line.match(/<\/span>/g) ?? []).length, `balanced: ${line}`)
  }
  assert.match(lines[1], /^<span class="hljs-comment">that spans lines \*\/<\/span>/, 'a comment continues onto the next line')

  // Discord gets the first lines as its description, and the language next to the site name.
  assert.equal(meta(html, 'og:description'), 'const greeting = &quot;hi&quot; /* a comment\nthat spans lines */\nfunction f() { return 42 }')
  assert.equal(meta(html, 'og:site_name'), 'SealDrop · JavaScript')
  assert.equal(html.match(/property="og:description"/g).length, 1)
})

test('plain text gets line numbers, and long files are cut with a note', async (t) => {
  const ctx = await startApp(t)
  const session = await ctx.login()
  const small = await (await fetch((await ctx.upload(session, 'one\ntwo\n', 'notes.txt')).pageUrl)).text()
  assert.match(small, /<span class="line">one<\/span><span class="line">two<\/span><\/code>/)

  const line = 'x'.repeat(99) + '\n'
  const big = await ctx.upload(session, line.repeat(6000), 'big.log')
  const html = await (await fetch(big.pageUrl)).text()
  assert.match(html, /Showing the first 512 KB\. Download the file for the rest\./)
  assert.ok(!html.includes('<span class="hljs'), 'huge text is shown plain')
})

test('text still downloads from its direct link, never shown inline', async (t) => {
  const ctx = await startApp(t)
  const file = await ctx.upload(await ctx.login(), '<!doctype html><h1>hi</h1>', 'page.html')
  assert.equal(file.kind, 'text')
  const response = await fetch(file.rawUrl)
  assert.equal(response.headers.get('content-type'), 'application/octet-stream')
  assert.match(response.headers.get('content-disposition'), /^attachment/)
  assert.equal(await response.text(), '<!doctype html><h1>hi</h1>')
  const html = await (await fetch(file.pageUrl)).text()
  assert.match(html, /<span class="text-lang">HTML, XML<\/span>/)
  assert.ok(html.includes('&lt;h1&gt;'))
})
