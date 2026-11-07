// Server-rendered HTML. Everything dynamic goes through esc().
import { languageLabel, renderText, textLanguage, textSnippet } from './textview.js'

export const esc = (value) => String(value).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
))

export function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = -1
  do {
    value /= 1024
    unit++
  } while (value >= 1024 && unit < units.length - 1)
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`
}

const page = ({ title, head = '', body, bodyClass = '', script = '', referrer = 'no-referrer' }) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="referrer" content="${referrer}">
<title>${esc(title)}</title>
${head}
<link rel="stylesheet" href="/static/style.css">
${script}
</head>
<body class="${bodyClass}">
${body}
</body>
</html>`

const logo = '<svg class="logo" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6.5c0 5 3.4 8.9 8 10.5 4.6-1.6 8-5.5 8-10.5V5l-8-3Zm0 6a2.5 2.5 0 0 1 1 4.8V16h-2v-3.2A2.5 2.5 0 0 1 12 8Z"/></svg>'

export function loginPage(config, error = '') {
  return page({
    title: `Sign in · ${config.siteName}`,
    bodyClass: 'center',
    referrer: 'same-origin',
    body: `<main class="card login">
  <h1 class="brand">${logo}${esc(config.siteName)}</h1>
  ${error ? `<p class="error" role="alert">${esc(error)}</p>` : ''}
  <form method="post" action="/login">
    <label>Password
      <input type="password" name="password" autocomplete="current-password" maxlength="1024" required autofocus>
    </label>
    <label>Authenticator code
      <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
    </label>
    <button class="primary" type="submit">Sign in</button>
  </form>
</main>`,
  })
}

export function dashboardPage(config, session) {
  return page({
    title: config.siteName,
    head: `<meta name="csrf-token" content="${esc(session.csrf)}">`,
    script: '<script src="/static/app.js" defer></script>',
    body: `<header class="topbar">
  <span class="brand">${logo}${esc(config.siteName)}</span>
  <button id="logout" class="ghost" type="button">Sign out</button>
</header>
<main class="wrap">
  <label id="drop" class="drop">
    <input id="picker" type="file" multiple>
    <strong>Drop files here</strong>
    <span>or click to choose. Each file gets its own secret link.</span>
  </label>
  <ul id="queue" class="queue"></ul>
  <h2>Your files <span id="count" class="muted"></span></h2>
  <p id="empty" class="muted" hidden>Nothing uploaded yet.</p>
  <ul id="files" class="files"></ul>
</main>
<div id="toast" class="toast" role="status" hidden></div>`,
  })
}

// A readable name for share links. Only the token matters to the server, so this is cosmetic.
function linkName(name) {
  const extension = /\.[A-Za-z0-9]{1,8}$/.exec(name)?.[0] ?? ''
  const stem = name.slice(0, name.length - extension.length)
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/-*\.-*/g, '.')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 60)
    .replace(/[-.]+$/, '')
  return (stem || 'file') + extension
}

// encodeURIComponent leaves ' ( ) * ! ~ as they are, and a shell treats most of those as
// syntax. With them encoded, a direct link can be pasted straight after wget or curl.
const shellSafeName = (name) =>
  encodeURIComponent(name).replace(/[!'()*~]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)

export const paths = {
  page: (token, name) => `/file/${token}/${linkName(name)}`,
  raw: (token, name) => `/raw/${token}/${shellSafeName(name)}`,
  download: (token, name) => `/download/${token}/${shellSafeName(name)}`,
  thumb: (token) => `/thumb/${token}.jpg`,
  embed: (token) => `/embed/${token}.mp4`,
}

// Images larger than this use the thumbnail in embeds, since Discord may refuse big ones.
const MAX_EMBED_IMAGE = 8 * 1024 * 1024

// `embed` is the Discord copy of a large video or of a sound file, when there is one.
// `text` is the start of a text file.
function embedTags(config, file, { embed, text }) {
  const { meta, token } = file
  const raw = config.origin + paths.raw(token, meta.name)
  const thumb = meta.hasThumb ? config.origin + paths.thumb(token) : null
  const tag = (property, content) => `<meta property="${property}" content="${esc(content)}">`
  const named = (name, content) => `<meta name="${name}" content="${esc(content)}">`
  const label = meta.kind === 'text' ? languageLabel(textLanguage(meta.name)) : null
  const tags = [
    tag('og:site_name', label ? `${config.siteName} · ${label}` : config.siteName),
    tag('og:title', meta.name),
    tag('og:description', text?.text ? textSnippet(text.text) : formatSize(meta.size)),
    tag('og:url', config.origin + paths.page(token, meta.name)),
    named('theme-color', '#5b6cff'),
  ]
  if (meta.kind === 'image') {
    const useRaw = meta.size <= MAX_EMBED_IMAGE || !thumb
    tags.push(tag('og:type', 'website'), tag('og:image', useRaw ? raw : thumb), named('twitter:card', 'summary_large_image'), named('twitter:image', useRaw ? raw : thumb))
    if (useRaw) tags.push(tag('og:image:type', meta.type))
    if (useRaw && meta.width) tags.push(tag('og:image:width', meta.width), tag('og:image:height', meta.height))
  } else if (meta.kind === 'video') {
    const video = embed ? config.origin + paths.embed(token) : raw
    const width = (embed ?? meta).width ?? 1280
    const height = (embed ?? meta).height ?? 720
    tags.push(
      tag('og:type', 'video.other'),
      tag('og:video', video), tag('og:video:url', video), tag('og:video:secure_url', video),
      tag('og:video:type', embed ? 'video/mp4' : meta.type), tag('og:video:width', width), tag('og:video:height', height),
      named('twitter:card', 'player'), named('twitter:player', video),
      named('twitter:player:width', width), named('twitter:player:height', height),
    )
    if (thumb) tags.push(tag('og:image', thumb), tag('og:image:type', 'image/jpeg'), tag('og:image:width', width), tag('og:image:height', height), named('twitter:image', thumb))
  } else if (meta.kind === 'audio') {
    // Discord has no audio player for links, so its player gets an MP4 of the sound with a
    // waveform. Without that copy, or without the picture Discord requires, it gets a card.
    if (embed && thumb) {
      const video = config.origin + paths.embed(token)
      tags.push(
        tag('og:type', 'video.other'),
        tag('og:video', video), tag('og:video:url', video), tag('og:video:secure_url', video),
        tag('og:video:type', 'video/mp4'), tag('og:video:width', embed.width), tag('og:video:height', embed.height),
        named('twitter:card', 'player'), named('twitter:player', video),
        named('twitter:player:width', embed.width), named('twitter:player:height', embed.height),
      )
    } else {
      tags.push(tag('og:type', 'music.song'), named('twitter:card', thumb ? 'summary_large_image' : 'summary'))
    }
    tags.push(tag('og:audio', raw), tag('og:audio:secure_url', raw), tag('og:audio:type', meta.type))
    if (thumb) tags.push(tag('og:image', thumb), tag('og:image:type', 'image/jpeg'), named('twitter:image', thumb))
  } else if (meta.kind === 'text') {
    tags.push(tag('og:type', 'website'), named('twitter:card', 'summary'))
  } else {
    tags.push(tag('og:type', 'website'))
  }
  return tags.join('\n')
}

// Share pages run no script, so this can't use the visitor's time zone. UTC is stated instead.
const uploadDate = new Intl.DateTimeFormat('en-US', {
  year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC',
})

function fileFacts(meta) {
  const fact = (label, value) => `<div class="fact"><dt>${label}</dt><dd>${value}</dd></div>`
  const uploaded = new Date(meta.createdAt)
  return `<dl class="facts">
    ${fact('Size', esc(formatSize(meta.size)))}
    ${fact('Uploaded', `<time datetime="${uploaded.toISOString()}">${esc(uploadDate.format(uploaded))} UTC</time>`)}
    ${meta.md5 ? fact('MD5', `<code>${esc(meta.md5)}</code>`) : ''}
  </dl>`
}

const fileLabel = (name) => /\.([A-Za-z0-9]{1,8})$/.exec(name)?.[1].toUpperCase() ?? 'FILE'

function plainFileBody(meta, download) {
  return `<main class="card file-card">
  <div class="file-card-info">
    <div class="file-icon" aria-hidden="true">${esc(fileLabel(meta.name))}</div>
    <h1>${esc(meta.name)}</h1>
    ${fileFacts(meta)}
  </div>
  <a class="button primary" href="${esc(download)}" download>Download</a>
</main>`
}

function shareInfo(meta, download) {
  return `<section class="card share-info">
    <div class="share-name">
      <h1>${esc(meta.name)}</h1>
      ${fileFacts(meta)}
    </div>
    <a class="button primary" href="${esc(download)}" download>Download</a>
  </section>`
}

function textBody(file, text, view, download) {
  const { meta, token } = file
  const language = textLanguage(meta.name)
  const label = languageLabel(language) ?? 'Text'
  const lines = text.text === '' ? 0 : text.text.split('\n').length - (text.text.endsWith('\n') ? 1 : 0)
  const pagePath = paths.page(token, meta.name)
  const toggle = language === 'markdown'
    ? `<nav class="text-views">${view === 'source'
      ? `<a href="${esc(pagePath)}">Rendered</a><span aria-current="page">Source</span>`
      : `<span aria-current="page">Rendered</span><a href="${esc(pagePath)}?view=source">Source</a>`}</nav>`
    : ''
  const note = text.truncated
    ? `<p class="text-note">Showing the first ${esc(formatSize(text.bytes))}. Download the file for the rest.</p>`
    : ''
  return `<main class="share share-text">
  <section class="card text-preview">
    <header class="text-head">
      <span class="text-lang">${esc(label)}</span>
      <span class="muted">${lines.toLocaleString('en-US')} ${lines === 1 ? 'line' : 'lines'}</span>
      ${toggle}
    </header>
    ${text.text === '' ? '<p class="text-note">This file is empty.</p>' : renderText(text.text, language, view)}
    ${note}
  </section>
  ${shareInfo(meta, download)}
</main>`
}

// `options.embed` is the Discord copy, `options.text` the start of a text file, and
// `options.view` picks rendered or source for Markdown.
export function sharePage(config, file, { embed = null, text = null, view = 'rendered' } = {}) {
  const { meta, token } = file
  const raw = paths.raw(token, meta.name)
  const download = paths.download(token, meta.name)
  const poster = meta.hasThumb ? ` poster="${paths.thumb(token)}"` : ''
  const cover = meta.hasThumb ? `<img class="preview audio-cover" src="${paths.thumb(token)}" alt="">` : ''
  const previews = {
    image: `<img class="preview" src="${esc(raw)}" alt="${esc(meta.name)}">`,
    video: `<video class="preview" src="${esc(raw)}" controls playsinline preload="metadata"${poster}></video>`,
    audio: `${cover}<audio class="preview-audio" src="${esc(raw)}" controls preload="metadata"></audio>`,
  }
  let body
  if (meta.kind === 'text' && text) body = textBody(file, text, view, download)
  else if (previews[meta.kind]) {
    body = `<main class="share">
  ${previews[meta.kind]}
  ${shareInfo(meta, download)}
</main>`
  } else body = plainFileBody(meta, download)
  return page({
    title: meta.name,
    head: embedTags(config, file, { embed, text }),
    bodyClass: 'center',
    body,
  })
}

export function notFoundPage(config) {
  return page({
    title: `Not found · ${config.siteName}`,
    bodyClass: 'center',
    body: `<main class="card login"><h1>Not found</h1><p class="muted">This link doesn't exist or has been removed.</p></main>`,
  })
}
