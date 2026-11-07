// Authentication for the single owner. There is deliberately no way to create a user here:
// the only identity is the one written by the setup command on the server itself.
import { randomBytes } from 'node:crypto'
import { readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { safeEqual, sha256, verifyTotp } from './crypto.js'
import { unlockOwner } from './owner.js'

export const DEVICES_FILE = 'devices.json'
const MINUTE = 60_000
export const IDLE_LIMIT = 120 * MINUTE
export const ABSOLUTE_LIMIT = 24 * 60 * MINUTE
export const FAIL_WINDOW = 15 * MINUTE
export const MAX_FAILS_PER_IP = 5
export const MAX_FAILS_GLOBAL = 20
const DEVICE_LIFETIME = 365 * 24 * 60 * MINUTE
const MAX_DEVICES = 20

export class Auth {
  #sessions = new Map()
  #ipFails = new Map()
  #globalFails = []
  #busy = false
  #lastStep = -1
  // Hashes of browsers that have signed in. Being on this list never grants access: it only
  // keeps that browser out of the global lockout, so an attacker can't lock the owner out by
  // failing logins on purpose. It has its own attempt limit instead.
  #devices = new Set()

  constructor({ owner, config, audit, now = Date.now }) {
    this.owner = owner
    this.config = config
    this.audit = audit
    this.now = now
    const prefix = config.secure ? '__Host-' : ''
    this.cookieName = `${prefix}sealdrop_session`
    this.deviceCookieName = `${prefix}sealdrop_device`
    this.statePath = join(config.dataDir, 'totp-state.json')
    this.devicesPath = join(config.dataDir, DEVICES_FILE)
  }

  // The last used TOTP step survives restarts, so a restart can't re-enable a used code.
  async init() {
    try {
      this.#lastStep = JSON.parse(await readFile(this.statePath, 'utf8')).lastStep
    } catch {
      this.#lastStep = -1
    }
    try {
      this.#devices = new Set(JSON.parse(await readFile(this.devicesPath, 'utf8')).devices)
    } catch {
      this.#devices = new Set()
    }
  }

  async #atomicWrite(path, value) {
    const temp = `${path}.tmp`
    await writeFile(temp, JSON.stringify(value), { mode: 0o600 })
    await rename(temp, path)
  }

  async #trustNewDevice() {
    const token = randomBytes(32).toString('base64url')
    this.#devices.add(sha256(token))
    for (const oldest of this.#devices) {
      if (this.#devices.size <= MAX_DEVICES) break
      this.#devices.delete(oldest)
    }
    await this.#atomicWrite(this.devicesPath, { devices: [...this.#devices] })
    return token
  }

  #recentFails(list, time) {
    return list.filter((at) => time - at < FAIL_WINDOW)
  }

  #isLocked(bucket, trusted, time) {
    this.#globalFails = this.#recentFails(this.#globalFails, time)
    if (this.#recentFails(this.#ipFails.get(bucket) ?? [], time).length >= MAX_FAILS_PER_IP) return true
    return !trusted && this.#globalFails.length >= MAX_FAILS_GLOBAL
  }

  #recordFail(bucket, trusted, ip, time) {
    if (!trusted) this.#globalFails.push(time)
    if (this.#ipFails.size > 10_000) this.#ipFails.clear()
    this.#ipFails.set(bucket, [...this.#recentFails(this.#ipFails.get(bucket) ?? [], time), time])
    this.audit('login_failed', { ip })
  }

  // Every failure looks identical, so an attacker can't tell which factor was wrong.
  async login({ password, code, ip, req }) {
    const time = this.now()
    const deviceToken = this.#cookieValue(req, this.deviceCookieName)
    const deviceHash = deviceToken ? sha256(deviceToken) : null
    const trusted = deviceHash !== null && this.#devices.has(deviceHash)
    const bucket = trusted ? `device:${deviceHash}` : ip
    if (this.#isLocked(bucket, trusted, time)) {
      this.audit('login_blocked', { ip })
      return { status: 429 }
    }
    if (this.#busy) return { status: 429 }
    this.#busy = true
    try {
      if (typeof password !== 'string' || password.length === 0 || password.length > 1024
        || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
        this.#recordFail(bucket, trusted, ip, time)
        return { status: 401 }
      }
      const secrets = await unlockOwner(this.owner, password)
      const step = secrets && verifyTotp(secrets.totpSecret, code, time, this.#lastStep)
      if (step === null || step === undefined) {
        this.#recordFail(bucket, trusted, ip, time)
        return { status: 401 }
      }
      this.#lastStep = step
      await this.#atomicWrite(this.statePath, { lastStep: step })
      this.#ipFails.delete(bucket)
      const newDevice = trusted ? null : await this.#trustNewDevice()
      const cookie = randomBytes(32).toString('base64url')
      this.#sessions.set(sha256(cookie), {
        masterKey: secrets.masterKey,
        csrf: randomBytes(32).toString('base64url'),
        createdAt: time,
        lastSeen: time,
        revoked: false,
      })
      this.audit('login_ok', { ip })
      return { status: 200, cookie, newDevice }
    } finally {
      this.#busy = false
    }
  }

  #cookie(name, value, maxAgeMs) {
    const secure = this.config.secure ? '; Secure' : ''
    return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure}`
  }

  sessionCookie(value, maxAgeMs) {
    return this.#cookie(this.cookieName, value, maxAgeMs)
  }

  deviceCookie(value) {
    return this.#cookie(this.deviceCookieName, value, DEVICE_LIFETIME)
  }

  #cookieValue(req, name = this.cookieName) {
    for (const part of (req.headers.cookie ?? '').split(';')) {
      const at = part.indexOf('=')
      if (at > 0 && part.slice(0, at).trim() === name) return part.slice(at + 1).trim()
    }
    return null
  }

  #revoke(key, session) {
    session.revoked = true
    session.masterKey.fill(0)
    this.#sessions.delete(key)
  }

  // Returns the live session for this request, or null.
  authenticate(req) {
    const value = this.#cookieValue(req)
    if (!value) return null
    const key = sha256(value)
    const session = this.#sessions.get(key)
    if (!session) return null
    const time = this.now()
    if (time - session.createdAt > ABSOLUTE_LIMIT || time - session.lastSeen > IDLE_LIMIT) {
      this.#revoke(key, session)
      return null
    }
    session.lastSeen = time
    return session
  }

  logout(req) {
    const value = this.#cookieValue(req)
    if (!value) return
    const key = sha256(value)
    const session = this.#sessions.get(key)
    if (session) this.#revoke(key, session)
  }

  // A cross-site request must fail even though the browser would attach the cookie.
  sameOrigin(req) {
    if (req.headers.origin !== this.config.origin) return false
    const site = req.headers['sec-fetch-site']
    return site === undefined || site === 'same-origin'
  }

  checkCsrf(req, session) {
    return this.sameOrigin(req) && safeEqual(req.headers['x-csrf-token'] ?? '', session.csrf)
  }
}
