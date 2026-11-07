// Text previews for share pages: Markdown rendered, code highlighted, everything else as
// plain text with line numbers. Rendering happens on the server, since share pages run
// no script. The output never contains markup from the file itself: highlight.js escapes
// everything, and Markdown's raw HTML is shown as text and its links are limited to
// http(s) and mailto. The share page's CSP (no script, no outside images) backs this up.
import hljs from 'highlight.js/lib/common'
import dockerfile from 'highlight.js/lib/languages/dockerfile'
import nginx from 'highlight.js/lib/languages/nginx'
import powershell from 'highlight.js/lib/languages/powershell'
import { Marked } from 'marked'

hljs.registerLanguage('dockerfile', dockerfile)
hljs.registerLanguage('nginx', nginx)
hljs.registerLanguage('powershell', powershell)

// Only this much is read for the page. Larger files say so and offer the download.
export const PREVIEW_BYTES = 512 * 1024
// Above this, text is shown plain: highlighting and Markdown get slow on huge input.
const RICH_BYTES = 200 * 1024

const esc = (value) => String(value).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
))

const NAMED = { dockerfile: 'dockerfile', makefile: 'makefile', gnumakefile: 'makefile', 'nginx.conf': 'nginx' }
const MARKDOWN = new Set(['md', 'markdown', 'mdown', 'mkd'])

// The language for display only, from the file name. The type and security decisions
// never depend on the name.
export function textLanguage(name) {
  const lower = name.toLowerCase()
  if (NAMED[lower]) return NAMED[lower]
  const ext = /\.([a-z0-9+_-]{1,12})$/.exec(lower)?.[1]
  if (!ext) return null
  if (MARKDOWN.has(ext)) return 'markdown'
  return hljs.getLanguage(ext) ? ext : null
}

export const languageLabel = (language) => (language ? hljs.getLanguage(language)?.name ?? null : null)

// Bytes from the start of a file, decoded. A character cut in half at the end is dropped.
export function decodePreview(bytes, truncated) {
  const text = new TextDecoder('utf-8').decode(bytes)
  return truncated ? text.replace(/�$/, '') : text
}

const LINK_PROTOCOLS = new Set(['http:', 'https:', 'mailto:'])

function safeHref(href) {
  if (typeof href !== 'string') return null
  if (href.startsWith('#')) return href
  try {
    const url = new URL(href)
    return LINK_PROTOCOLS.has(url.protocol) ? url.href : null
  } catch {
    return null // relative links would point into this site, so they aren't links here
  }
}

function highlight(code, language) {
  if (language && hljs.getLanguage(language)) {
    return hljs.highlight(code, { language, ignoreIllegals: true }).value
  }
  return esc(code)
}

const markdown = new Marked({
  gfm: true,
  renderer: {
    html({ text }) {
      return esc(text)
    },
    link({ href, tokens }) {
      const text = this.parser.parseInline(tokens)
      const safe = safeHref(href)
      return safe ? `<a href="${esc(safe)}" rel="nofollow noopener noreferrer ugc">${text}</a>` : text
    },
    // Images from elsewhere are blocked by the page's policy anyway, so they become links.
    image({ href, text }) {
      const safe = safeHref(href)
      const label = esc(text || 'image')
      return safe ? `<a href="${esc(safe)}" rel="nofollow noopener noreferrer ugc">[${label}]</a>` : `[${label}]`
    },
    code({ text, lang }) {
      const language = lang?.split(/\s/)[0].toLowerCase()
      return `<pre class="code-block"><code class="hljs">${highlight(text, language)}</code></pre>\n`
    },
  },
})

// highlight.js output may open a span on one line and close it on a later one. Each line
// is closed and reopened so it stands alone, which lets every line get its own number.
function splitLines(html) {
  const lines = []
  const open = []
  let current = ''
  for (const [piece] of html.matchAll(/<span class="[^"]*">|<\/span>|\n|[^<\n]+/g)) {
    if (piece === '\n') {
      lines.push(current + '</span>'.repeat(open.length))
      current = open.join('')
    } else if (piece === '</span>') {
      open.pop()
      current += piece
    } else {
      if (piece.startsWith('<span')) open.push(piece)
      current += piece
    }
  }
  lines.push(current + '</span>'.repeat(open.length))
  if (lines.length > 1 && lines.at(-1) === '') lines.pop()
  return lines
}

function codeView(text, language) {
  const lines = splitLines(highlight(text, language))
  return `<pre class="code"><code class="hljs">${lines.map((line) => `<span class="line">${line}</span>`).join('')}</code></pre>`
}

// Returns the preview's HTML. `view` is 'rendered' or 'source', and only matters for Markdown.
export function renderText(text, language, view) {
  if (text.length > RICH_BYTES) return codeView(text, null)
  if (language === 'markdown' && view !== 'source') {
    return `<article class="markdown">${markdown.parse(text)}</article>`
  }
  return codeView(text, language)
}

// A few lines for Discord's description. Discord shortens long ones itself.
export function textSnippet(text) {
  const lines = text.replace(/\r\n?/g, '\n').split('\n').slice(0, 12).join('\n').trim()
  return lines.length > 300 ? `${lines.slice(0, 299)}…` : lines
}
