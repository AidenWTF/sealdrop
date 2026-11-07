// Owner dashboard. File names are only ever inserted with textContent.
const csrf = document.querySelector('meta[name="csrf-token"]').content
const $ = (id) => document.getElementById(id)
let active = 0
let toastTimer
let allFiles = []
const selected = new Set()

function toast(message) {
  const el = $('toast')
  el.textContent = message
  el.hidden = false
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { el.hidden = true }, 2500)
}

function formatSize(bytes) {
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

function el(tag, className, text) {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== undefined) node.textContent = text
  return node
}

async function copy(text, message) {
  try {
    await navigator.clipboard.writeText(text)
    toast(message)
  } catch {
    window.prompt('Copy this link:', text)
  }
}

// When the link stops working, and how its Discord copy is doing.
function fileNotes(file) {
  const notes = []
  if (file.expiresAt) {
    const hours = Math.max(0, (file.expiresAt - Date.now()) / 3_600_000)
    notes.push(hours < 1 ? 'expires within the hour' : hours < 48 ? `expires in ${Math.round(hours)} h` : `expires in ${Math.round(hours / 24)} days`)
  }
  if (file.maxDownloads) notes.push(`${file.maxDownloads - (file.downloads ?? 0)} of ${file.maxDownloads} downloads left`)
  const discord = {
    ready: 'Discord copy ready',
    pending: 'Discord copy being made',
    skipped: `no Discord copy (${file.discord?.reason})`,
  }[file.discord?.status]
  if (discord) notes.push(discord)
  return notes
}

function fileRow(file) {
  const row = el('li', 'file')
  const pick = el('input', 'pick')
  pick.type = 'checkbox'
  pick.checked = selected.has(file.token)
  pick.setAttribute('aria-label', `Select ${file.name}`)
  pick.onchange = () => {
    if (pick.checked) selected.add(file.token)
    else selected.delete(file.token)
    showSelection()
  }
  let thumb
  if (file.thumbUrl) {
    thumb = el('img', 'thumb')
    thumb.src = file.thumbUrl
    thumb.alt = ''
    thumb.loading = 'lazy'
  } else {
    thumb = el('div', 'thumb', file.kind === 'file' ? 'File' : file.kind)
  }

  const text = el('div', 'file-text')
  const name = el('a', 'file-name', file.name)
  name.href = file.pageUrl
  name.target = '_blank'
  name.rel = 'noopener noreferrer'
  const date = new Date(file.createdAt).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
  text.append(name, el('div', 'file-meta', [`${formatSize(file.size)} · ${date}`, ...fileNotes(file)].join(' · ')))

  const actions = el('div', 'actions')
  const copyLink = el('button', 'primary', 'Copy link')
  copyLink.type = 'button'
  copyLink.onclick = () => copy(file.pageUrl, 'Link copied')
  const copyDirect = el('button', '', 'Direct link')
  copyDirect.type = 'button'
  copyDirect.title = 'Link straight to the file, with no page around it'
  copyDirect.onclick = () => copy(file.rawUrl, 'Direct link copied')
  const remove = el('button', 'danger', 'Delete')
  remove.type = 'button'
  remove.onclick = () => removeFile(file)
  actions.append(copyLink, copyDirect, remove)

  row.append(pick, thumb, text, actions)
  return row
}

function showSelection() {
  const button = $('delete-selected')
  button.hidden = selected.size === 0
  button.textContent = `Delete ${selected.size} selected`
}

function showFiles() {
  const query = $('search').value.trim().toLowerCase()
  const shown = query ? allFiles.filter((f) => f.name.toLowerCase().includes(query)) : allFiles
  $('files').replaceChildren(...shown.map(fileRow))
  $('empty').hidden = allFiles.length > 0
  $('empty').textContent = 'Nothing uploaded yet.'
  if (allFiles.length && !shown.length) {
    $('empty').hidden = false
    $('empty').textContent = 'No file names match.'
  }
  $('count').textContent = allFiles.length ? `(${allFiles.length})` : ''
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': csrf, ...options.headers },
  })
  if (response.status === 401) {
    window.location.replace('/')
    throw new Error('signed out')
  }
  return response
}

async function refresh() {
  const response = await api('/api/files')
  if (!response.ok) throw new Error('could not load files')
  const { files, storage } = await response.json()
  allFiles = files
  for (const token of selected) if (!files.some((f) => f.token === token)) selected.delete(token)
  showFiles()
  showSelection()
  $('storage').textContent = `${formatSize(storage.files)} in files${storage.copies ? ` + ${formatSize(storage.copies)} Discord copies` : ''}`
  // Copies are made in the background, so check back while any are on their way.
  clearTimeout(refreshTimer)
  if (files.some((f) => f.discord?.status === 'pending')) refreshTimer = setTimeout(() => refresh().catch(() => {}), 10_000)
}
let refreshTimer

async function removeFile(file) {
  if (!window.confirm(`Delete "${file.name}"? Its link stops working immediately. This can't be undone.`)) return
  const response = await api(`/api/files/${file.token}`, { method: 'DELETE' })
  toast(response.ok ? 'Deleted' : 'Could not delete')
  await refresh()
}

function uploadOne(file) {
  return new Promise((resolve) => {
    const item = el('li')
    const row = el('div', 'row')
    const status = el('span', 'muted', 'Waiting')
    row.append(el('span', 'name', file.name), status)
    const bar = el('progress')
    bar.max = 1
    bar.value = 0
    item.append(row, bar)
    $('queue').append(item)

    const fail = (message) => {
      status.textContent = message
      status.className = 'failed'
      bar.remove()
      resolve(false)
    }

    const xhr = new XMLHttpRequest()
    xhr.open('POST', '/api/upload')
    xhr.setRequestHeader('X-CSRF-Token', csrf)
    xhr.setRequestHeader('X-File-Name', encodeURIComponent(file.name))
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    if ($('expires').value) xhr.setRequestHeader('X-Expires-In', $('expires').value)
    const limit = $('max-downloads').value.trim()
    if (limit) xhr.setRequestHeader('X-Max-Downloads', limit)
    if (!$('strip').checked) xhr.setRequestHeader('X-Keep-Metadata', '1')
    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return
      bar.value = event.loaded / event.total
      status.textContent = event.loaded === event.total ? 'Encrypting and building preview' : `${Math.floor((event.loaded / event.total) * 100)}%`
    }
    xhr.onerror = () => fail('Upload failed')
    xhr.onload = () => {
      if (xhr.status === 201) {
        item.remove()
        resolve(true)
      } else if (xhr.status === 401) {
        window.location.replace('/')
      } else {
        fail({ 413: 'Too large', 400: 'Check the expiry and download limit', 422: 'This photo could not be cleaned. Untick the location option to upload it as it is.' }[xhr.status] ?? 'Upload failed')
      }
    }
    xhr.send(file)
  })
}

async function uploadAll(fileList) {
  const files = Array.from(fileList)
  active += files.length
  for (const file of files) {
    if (await uploadOne(file)) {
      toast('Uploaded')
      await refresh()
    }
    active--
  }
}

$('search').addEventListener('input', showFiles)

$('delete-selected').addEventListener('click', async () => {
  const count = selected.size
  if (!window.confirm(`Delete ${count} ${count === 1 ? 'file' : 'files'}? Their links stop working immediately. This can't be undone.`)) return
  let failed = 0
  for (const token of [...selected]) {
    const response = await api(`/api/files/${token}`, { method: 'DELETE' })
    if (response.ok || response.status === 404) selected.delete(token)
    else failed++
  }
  toast(failed ? `${failed} could not be deleted` : 'Deleted')
  await refresh()
})

// The upload choices are remembered in this browser.
for (const id of ['expires', 'strip']) {
  try {
    const saved = localStorage.getItem(`sealdrop:${id}`)
    if (saved !== null) {
      if (id === 'strip') $(id).checked = saved === '1'
      else $(id).value = saved
    }
  } catch {}
  $(id).addEventListener('change', () => {
    try {
      localStorage.setItem(`sealdrop:${id}`, id === 'strip' ? ($(id).checked ? '1' : '0') : $(id).value)
    } catch {}
  })
}

$('picker').addEventListener('change', (event) => {
  uploadAll(event.target.files)
  event.target.value = ''
})

const drop = $('drop')
for (const name of ['dragenter', 'dragover']) {
  window.addEventListener(name, (event) => {
    event.preventDefault()
    drop.classList.add('over')
  })
}
window.addEventListener('dragleave', (event) => {
  if (!event.relatedTarget) drop.classList.remove('over')
})
window.addEventListener('drop', (event) => {
  event.preventDefault()
  drop.classList.remove('over')
  if (event.dataTransfer?.files.length) uploadAll(event.dataTransfer.files)
})

window.addEventListener('beforeunload', (event) => {
  if (active > 0) event.preventDefault()
})

$('logout').addEventListener('click', async () => {
  await api('/logout', { method: 'POST' }).catch(() => {})
  window.location.replace('/')
})

// Passkeys
const toBytes = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
const toText = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const shortDate = (time) => new Date(time).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })

function showSecurity({ passkeys, codesAllowed }) {
  $('passkeys').replaceChildren(...passkeys.map((passkey) => {
    const row = el('li', 'passkey')
    const text = el('div')
    text.append(el('strong', '', passkey.name), el('div', 'muted small',
      `Added ${shortDate(passkey.createdAt)} · ${passkey.lastUsedAt ? `last used ${shortDate(passkey.lastUsedAt)}` : 'not used yet'}`))
    const remove = el('button', 'danger', 'Remove')
    remove.type = 'button'
    remove.onclick = async () => {
      if (!window.confirm(`Remove the passkey "${passkey.name}"? It can no longer be used to sign in.`)) return
      const response = await api(`/api/passkeys/${passkey.id}`, { method: 'DELETE' })
      if (response.ok) showSecurity(await response.json())
      toast(response.ok ? 'Passkey removed' : 'Could not remove it')
    }
    row.append(text, remove)
    return row
  }))
  const toggle = $('codes-allowed')
  toggle.checked = codesAllowed
  toggle.disabled = passkeys.length === 0
  $('codes-note').textContent = passkeys.length === 0
    ? 'Add a passkey to be able to turn authenticator codes off.'
    : codesAllowed
      ? 'Codes still work as a backup. Turn them off to sign in with passkeys only.'
      : 'Only passkeys work. If you lose them, run setup on the server to turn codes back on.'
}

async function loadSecurity() {
  const response = await api('/api/passkeys')
  if (response.ok) showSecurity(await response.json())
}

$('add-passkey')?.addEventListener('click', async () => {
  if (!('PublicKeyCredential' in window)) return toast('This browser does not support passkeys')
  const name = window.prompt('A name for this passkey, so you can tell it apart later:', 'Passkey')
  if (name === null) return
  try {
    const options = await (await api('/api/passkeys/options', { method: 'POST' })).json()
    const credential = await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: toBytes(options.challenge),
        user: { ...options.user, id: toBytes(options.user.id) },
        excludeCredentials: options.excludeCredentials.map((c) => ({ ...c, id: toBytes(c.id) })),
      },
    })
    const response = await api('/api/passkeys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        response: {
          clientDataJSON: toText(credential.response.clientDataJSON),
          attestationObject: toText(credential.response.attestationObject),
        },
      }),
    })
    if (!response.ok) return toast('That passkey could not be added')
    showSecurity(await response.json())
    toast('Passkey added')
  } catch (err) {
    toast(err?.name === 'InvalidStateError' ? 'That passkey is already added' : 'Passkey not added')
  }
})

$('codes-allowed')?.addEventListener('change', async (event) => {
  const allowed = event.target.checked
  if (!allowed && !window.confirm('Turn off authenticator codes? You will need a passkey to sign in.')) {
    event.target.checked = true
    return
  }
  const response = await api('/api/settings/codes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ allowed }),
  })
  if (response.ok) showSecurity(await response.json())
  else event.target.checked = !allowed
  toast(response.ok ? (allowed ? 'Codes turned on' : 'Codes turned off') : 'Could not change that')
})

refresh().catch(() => toast('Could not load your files'))
// Only the owner has sign-in settings here; people from the OIDC provider manage theirs there.
if ($('security')) loadSecurity().catch(() => {})
