// Authentication for the single owner. There is deliberately no way to create a user here:
// the only identity is the one written by the setup command on the server itself.
import { randomBytes } from 'node:crypto'
import { readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { safeEqual, sha256, verifyTotp } from './crypto.js'
import { unlockOwner } from './owner.js'
import { MAX_PASSKEYS, passkeyHints, readPasskeys, writePasskeys } from './passkeys.js'
import { ALGORITHMS, b64url, fromB64url, verifyAssertion, verifyRegistration } from './webauthn.js'

export const DEVICES_FILE = 'devices.json'
const MINUTE = 60_000
export const IDLE_LIMIT = 120 * MINUTE
export const ABSOLUTE_LIMIT = 24 * 60 * MINUTE
export const FAIL_WINDOW = 15 * MINUTE
export const MAX_FAILS_PER_IP = 5
export const MAX_FAILS_GLOBAL = 20
const DEVICE_LIFETIME = 365 * 24 * 60 * MINUTE
const MAX_DEVICES = 20
// Passkey challenges are single use and short lived. Anyone can ask for one, so there's a cap.
const CHALLENGE_LIFETIME = 5 * MINUTE
const MAX_CHALLENGES = 100

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
  #challenges = new Map()
  // What the login page offers. Read without the master key, so it's never trusted.
  hints = { hasPasskeys: false, codesAllowed: true }

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
    this.rpId = new URL(config.origin).hostname
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
    this.hints = await passkeyHints(this.config.dataDir)
  }

  #expected(challenge) {
    return { challenge, origin: this.config.origin, rpId: this.rpId, requireUserVerification: false }
  }

  // For the login page. Any passkey for this site may answer, so no passkey ids are given out.
  loginChallenge() {
    const time = this.now()
    for (const [key, expires] of this.#challenges) {
      if (expires < time || this.#challenges.size >= MAX_CHALLENGES) this.#challenges.delete(key)
    }
    const challenge = randomBytes(32)
    this.#challenges.set(b64url(challenge), time + CHALLENGE_LIFETIME)
    return { challenge: b64url(challenge), rpId: this.rpId, timeout: CHALLENGE_LIFETIME }
  }

  // The challenge a login assertion answers, if this server issued it and it's unused.
  #takeChallenge(passkey) {
    let issued
    try {
      issued = JSON.parse(fromB64url(passkey?.clientDataJSON)?.toString('utf8') ?? 'null')?.challenge
    } catch {
      return null
    }
    const expires = typeof issued === 'string' ? this.#challenges.get(issued) : undefined
    if (expires === undefined) return null
    this.#challenges.delete(issued)
    return expires >= this.now() ? fromB64url(issued) : null
  }

  async #savePasskeys(masterKey, state) {
    await writePasskeys(this.config.dataDir, masterKey, state)
    this.hints = await passkeyHints(this.config.dataDir)
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
  // The second factor is either an authenticator `code` or a `passkey` assertion.
  async login({ password, code, passkey, ip, req }) {
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
      const usesPasskey = passkey !== null && typeof passkey === 'object'
      const challenge = usesPasskey ? this.#takeChallenge(passkey) : null
      if (typeof password !== 'string' || password.length === 0 || password.length > 1024
        || (usesPasskey ? !challenge : typeof code !== 'string' || !/^\d{6}$/.test(code))) {
        this.#recordFail(bucket, trusted, ip, time)
        return { status: 401 }
      }
      const secrets = await unlockOwner(this.owner, password)
      const stored = secrets && await readPasskeys(this.config.dataDir, secrets.masterKey)
      if (stored?.tampered) this.audit('passkeys_tampered', {})
      let step = null
      let signed = null
      if (stored && usesPasskey) {
        try {
          signed = verifyAssertion(passkey, this.#expected(challenge), stored.passkeys)
        } catch {
          signed = null
        }
      } else if (stored && stored.codesAllowed) {
        step = verifyTotp(secrets.totpSecret, code, time, this.#lastStep)
      }
      if (!signed && (step === null || step === undefined)) {
        this.#recordFail(bucket, trusted, ip, time)
        return { status: 401 }
      }
      if (signed) {
        signed.passkey.signCount = signed.signCount
        signed.passkey.lastUsedAt = time
        await this.#savePasskeys(secrets.masterKey, stored)
      } else {
        this.#lastStep = step
        await this.#atomicWrite(this.statePath, { lastStep: step })
      }
      this.#ipFails.delete(bucket)
      const newDevice = trusted ? null : await this.#trustNewDevice()
      const cookie = this.createSession({ masterKey: secrets.masterKey })
      this.audit('login_ok', { ip, method: signed ? 'passkey' : 'code' })
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

  cookieValue(req, name) {
    return this.#cookieValue(req, name)
  }

  #cookieValue(req, name = this.cookieName) {
    for (const part of (req.headers.cookie ?? '').split(';')) {
      const at = part.indexOf('=')
      if (at > 0 && part.slice(0, at).trim() === name) return part.slice(at + 1).trim()
    }
    return null
  }

  // A new session. `member` is { id, name } for someone signed in through OIDC, and null
  // for the owner. Returns the cookie value.
  createSession({ masterKey, member = null }) {
    const time = this.now()
    const cookie = randomBytes(32).toString('base64url')
    this.#sessions.set(sha256(cookie), {
      masterKey,
      member,
      csrf: randomBytes(32).toString('base64url'),
      createdAt: time,
      lastSeen: time,
      revoked: false,
    })
    return cookie
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

  // Passkey management, for a signed-in owner. The session holds the master key that the
  // passkey list is authenticated with.
  async passkeySettings(session) {
    const { passkeys, codesAllowed } = await readPasskeys(this.config.dataDir, session.masterKey)
    return {
      codesAllowed,
      passkeys: passkeys.map(({ id, name, createdAt, lastUsedAt }) => ({ id, name, createdAt, lastUsedAt })),
    }
  }

  async registrationOptions(session) {
    const { passkeys } = await readPasskeys(this.config.dataDir, session.masterKey)
    const challenge = randomBytes(32)
    session.registration = { challenge, expires: this.now() + CHALLENGE_LIFETIME }
    return {
      challenge: b64url(challenge),
      rp: { id: this.rpId, name: this.config.siteName },
      // One owner, so one fixed user handle per site.
      user: { id: b64url(sha256(`sealdrop-owner:${this.config.origin}`).slice(0, 32)), name: 'owner', displayName: this.config.siteName },
      pubKeyCredParams: ALGORITHMS.map((alg) => ({ type: 'public-key', alg })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: passkeys.map(({ id }) => ({ type: 'public-key', id })),
      attestation: 'none',
      timeout: CHALLENGE_LIFETIME,
    }
  }

  async addPasskey(session, { name, response }) {
    const pending = session.registration
    session.registration = null
    if (!pending || pending.expires < this.now()) throw new Error('no registration in progress')
    const added = verifyRegistration(response, this.#expected(pending.challenge))
    const state = await readPasskeys(this.config.dataDir, session.masterKey)
    if (state.passkeys.some((p) => p.id === added.id)) throw new Error('already added')
    if (state.passkeys.length >= MAX_PASSKEYS) throw new Error('too many passkeys')
    const label = typeof name === 'string' && name.trim() ? name.trim().slice(0, 60) : 'Passkey'
    state.passkeys.push({ ...added, name: label, createdAt: this.now(), lastUsedAt: null })
    await this.#savePasskeys(session.masterKey, state)
  }

  async removePasskey(session, id) {
    const state = await readPasskeys(this.config.dataDir, session.masterKey)
    const remaining = state.passkeys.filter((p) => p.id !== id)
    if (remaining.length === state.passkeys.length) return false
    await this.#savePasskeys(session.masterKey, { ...state, passkeys: remaining })
    return true
  }

  // Turning codes off leaves passkeys as the only second factor. Not allowed without one.
  async setCodesAllowed(session, allowed) {
    const state = await readPasskeys(this.config.dataDir, session.masterKey)
    if (!allowed && state.passkeys.length === 0) return false
    await this.#savePasskeys(session.masterKey, { ...state, codesAllowed: allowed })
    return true
  }
}
