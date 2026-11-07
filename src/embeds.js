// Makes the Discord copies in the background, one at a time: a smaller copy of each large
// video, and an MP4 with a waveform for each sound file, since Discord can't play audio links.
//
// ffmpeg needs a file it can seek in to put the MP4 index at the front, so the copy is
// written to /dev/shm, which is memory, not disk. That is no more exposed than the app's
// own memory, and the copy is encrypted into the data directory and deleted right after.
// Without /dev/shm (outside Linux) no copies are made.
//
// Work is keyed by link token, which only the upload and the signed-in dashboard know.
// After a restart nothing is queued until the owner opens the dashboard, which queues
// whatever is still missing. A failed attempt is recorded and not retried.
import { createHash, randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { readdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { makeEmbedCopy } from './media.js'

export const RAM_DIR = '/dev/shm'

export function createEmbedQueue({ store, config, audit, ramDir = RAM_DIR }) {
  const enabled = config.discordCopies && existsSync(ramDir)
  // Scoped to this data directory, so a cleanup never touches another instance's work.
  const prefix = `sealdrop-${createHash('sha256').update(config.dataDir).digest('hex').slice(0, 12)}-`
  const pending = new Map()
  let running = null

  const wanted = (file) => enabled && (
    file.meta.kind === 'audio' || (file.meta.kind === 'video' && file.meta.size > config.discordCopyOverBytes)
  )

  async function makeCopy(token) {
    const file = await store.load(token)
    if (!file || await store.embed(file)) return
    const out = join(ramDir, `${prefix}${randomBytes(8).toString('hex')}.mp4`)
    try {
      const result = await makeEmbedCopy(file.read, file.meta, config, out)
      if (result.skip) {
        await store.skipEmbed(file, result.skip)
        audit('embed_skipped', { reason: result.skip })
      } else {
        await store.saveEmbed(file, out, result)
        audit('embed_ok')
      }
    } catch (err) {
      // Most often the file was deleted while its copy was being made.
      if (await store.load(token)) {
        await store.skipEmbed(file, 'failed').catch(() => {})
        audit('embed_error', { code: err.code ?? 'unknown' })
      }
    } finally {
      await rm(out, { force: true })
    }
  }

  async function drain() {
    while (pending.size) {
      const [id, token] = pending.entries().next().value
      try {
        await makeCopy(token)
      } catch (err) {
        audit('embed_error', { code: err.code ?? 'unknown' })
      } finally {
        pending.delete(id)
      }
    }
  }

  // Anything queued while the last run was finishing starts a new run.
  function kick() {
    if (running) return
    running = drain().finally(() => {
      running = null
      if (pending.size) kick()
    })
  }

  return {
    enabled,
    wanted,
    queued: (file) => pending.has(file.keys.id),

    async init() {
      if (!existsSync(ramDir)) return
      // A crash mid-encode would leave a plaintext copy in memory until reboot.
      for (const name of await readdir(ramDir)) {
        if (name.startsWith(prefix)) await rm(join(ramDir, name), { force: true })
      }
    },

    // Queues a copy if this file should have one and doesn't yet. Returns at once.
    async consider(file) {
      if (!wanted(file) || pending.has(file.keys.id) || await store.embed(file)) return
      pending.set(file.keys.id, file.token)
      kick()
    },

    // Resolves once nothing is queued or running. For tests.
    async idle() {
      while (running) await running
    },
  }
}
