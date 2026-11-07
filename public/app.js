// Owner dashboard. File names are only ever inserted with textContent.
const csrf = document.querySelector('meta[name="csrf-token"]').content
const $ = (id) => document.getElementById(id)
let active = 0
let toastTimer

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

function fileRow(file) {
  const row = el('li', 'file')
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
  text.append(name, el('div', 'file-meta', `${formatSize(file.size)} · ${date}`))

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

  row.append(thumb, text, actions)
  return row
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
  const { files } = await response.json()
  $('files').replaceChildren(...files.map(fileRow))
  $('empty').hidden = files.length > 0
  $('count').textContent = files.length ? `(${files.length})` : ''
}

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
        fail(xhr.status === 413 ? 'Too large' : 'Upload failed')
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

refresh().catch(() => toast('Could not load your files'))
