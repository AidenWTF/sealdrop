// A picture of the first lines of a text file, for Discord's embed and the dashboard. It is
// drawn as SVG and turned into a JPEG. Every piece of text from the file is XML-escaped, and
// the SVG refers to nothing outside itself, so the renderer has nothing to fetch.
import { highlight, languageLabel, splitLines, textLanguage } from './textview.js'

export const CODE_IMAGE = { width: 1200, height: 630 }
const MAX_LINES = 18
const MAX_COLUMNS = 88
const FONT_SIZE = 20
const LINE_HEIGHT = 28
const LEFT = 104
const TOP = 112

// The dark theme's highlighting colours, as on the share page.
const COLORS = {
  keyword: '#e38bd8', 'selector-tag': '#e38bd8', built_in: '#e38bd8', literal: '#e38bd8', doctag: '#e38bd8',
  string: '#8fd18b', regexp: '#8fd18b', addition: '#8fd18b', 'template-string': '#8fd18b', symbol: '#8fd18b',
  number: '#f0b36d', bullet: '#f0b36d',
  comment: '#7f8698', quote: '#7f8698',
  title: '#8fa0ff', section: '#8fa0ff', name: '#8fa0ff', 'selector-id': '#8fa0ff', 'selector-class': '#8fa0ff',
  type: '#6fd3e0',
  attr: '#f0c674', attribute: '#f0c674', property: '#f0c674', params: '#f0c674', variable: '#f0c674',
  meta: '#b6a8ff', tag: '#b6a8ff', 'template-variable': '#b6a8ff', link: '#b6a8ff',
  deletion: '#ff7782',
}
const TEXT = '#e9ebf0'

const xml = (text) => text.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]))
const unescapeHtml = (text) => text.replace(/&(amp|lt|gt|quot|#x27|#39);/g, (_, e) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#x27': "'", '#39': "'" }[e]))

// One highlighted line as coloured runs, cut to the visible width.
function runs(lineHtml) {
  const out = []
  const stack = []
  let used = 0
  for (const [piece] of lineHtml.matchAll(/<span class="([^"]*)">|<\/span>|[^<]+/g)) {
    if (piece.startsWith('<span')) {
      const classes = /class="([^"]*)"/.exec(piece)[1].split(/\s+/).map((c) => c.replace(/^hljs-/, ''))
      stack.push(classes.map((c) => COLORS[c]).find(Boolean) ?? stack.at(-1) ?? null)
    } else if (piece === '</span>') {
      stack.pop()
    } else {
      let text = unescapeHtml(piece)
      if (used >= MAX_COLUMNS) continue
      if (used + text.length > MAX_COLUMNS) text = `${text.slice(0, MAX_COLUMNS - used - 1)}…`
      used += text.length
      out.push({ text, color: stack.at(-1) ?? TEXT })
    }
  }
  return out
}

export function codeSvg(text, name) {
  const language = textLanguage(name)
  const source = text.replace(/\r\n?/g, '\n').replace(/\t/g, '    ')
  const lines = splitLines(highlight(source.split('\n').slice(0, MAX_LINES).join('\n'), language === 'markdown' ? 'markdown' : language))
  const label = languageLabel(language) ?? 'Text'
  const title = name.length > 60 ? `${name.slice(0, 59)}…` : name
  const rows = lines.map((line, i) => {
    const y = TOP + i * LINE_HEIGHT
    const spans = runs(line).map((r) => `<tspan fill="${r.color}">${xml(r.text)}</tspan>`).join('')
    return `<text x="${LEFT - 24}" y="${y}" text-anchor="end" fill="#5d6475">${i + 1}</text><text x="${LEFT}" y="${y}">${spans}</text>`
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${CODE_IMAGE.width}" height="${CODE_IMAGE.height}" viewBox="0 0 ${CODE_IMAGE.width} ${CODE_IMAGE.height}">
<rect width="100%" height="100%" fill="#101218"/>
<rect x="24" y="24" width="${CODE_IMAGE.width - 48}" height="${CODE_IMAGE.height - 48}" rx="16" fill="#191c24" stroke="#2b2f3a"/>
<circle cx="56" cy="58" r="7" fill="#ff7782"/><circle cx="80" cy="58" r="7" fill="#f0c674"/><circle cx="104" cy="58" r="7" fill="#8fd18b"/>
<text x="128" y="65" font-family="DejaVu Sans, Noto Sans, sans-serif" font-size="20" font-weight="bold" fill="${TEXT}">${xml(title)}</text>
<text x="${CODE_IMAGE.width - 52}" y="65" text-anchor="end" font-family="DejaVu Sans, Noto Sans, sans-serif" font-size="18" fill="#979eae">${xml(label)}</text>
<line x1="24" y1="84" x2="${CODE_IMAGE.width - 24}" y2="84" stroke="#2b2f3a"/>
<g font-family="DejaVu Sans Mono, Noto Sans Mono, Liberation Mono, monospace" font-size="${FONT_SIZE}" xml:space="preserve">${rows}</g>
</svg>`
}
