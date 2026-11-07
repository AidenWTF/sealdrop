// Sign-in through an OpenID Connect provider such as Pocket ID, with Node's built-in
// crypto only: the authorization code flow with PKCE, and the ID token's signature,
// issuer, audience, lifetime and nonce all checked here.
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto'

const b64url = (buffer) => Buffer.from(buffer).toString('base64url')
const FLOW_LIFETIME = 10 * 60_000
const MAX_FLOWS = 200
const CLOCK_SKEW = 60

export class OidcError extends Error {}

// Signature algorithms ID tokens may use, and how Node verifies each.
const ALGORITHMS = {
  RS256: { hash: 'sha256' },
  RS384: { hash: 'sha384' },
  RS512: { hash: 'sha512' },
  PS256: { hash: 'sha256', pss: true },
  ES256: { hash: 'sha256', ec: true },
  ES384: { hash: 'sha384', ec: true },
  EdDSA: { hash: null },
}

export class Oidc {
  #flows = new Map()
  #discovery = null
  #jwks = null

  // `fetchFn` is replaceable for tests. `now` is milliseconds.
  constructor({ issuer, clientId, clientSecret, redirectUri, allowedGroup, now = Date.now, fetchFn = fetch }) {
    this.issuer = issuer.replace(/\/+$/, '')
    this.clientId = clientId
    this.clientSecret = clientSecret || null
    this.redirectUri = redirectUri
    this.allowedGroup = allowedGroup || null
    this.now = now
    this.fetch = fetchFn
  }

  async #json(url, options) {
    const response = await this.fetch(url, { ...options, signal: AbortSignal.timeout(10_000), redirect: 'error' })
    if (!response.ok) throw new OidcError(`provider answered ${response.status}`)
    return response.json()
  }

  async discovery() {
    if (this.#discovery && this.#discovery.expires > this.now()) return this.#discovery.value
    const value = await this.#json(`${this.issuer}/.well-known/openid-configuration`)
    if (value.issuer !== this.issuer) throw new OidcError('discovery names a different issuer')
    for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
      if (typeof value[key] !== 'string' || !value[key].startsWith('https://') && !value[key].startsWith('http://127.0.0.1')) {
        throw new OidcError(`discovery has no usable ${key}`)
      }
    }
    this.#discovery = { value, expires: this.now() + 60 * 60_000 }
    return value
  }

  async #key(kid, alg, refetch = true) {
    if (!this.#jwks || this.#jwks.expires < this.now()) {
      this.#jwks = { keys: (await this.#json((await this.discovery()).jwks_uri)).keys ?? [], expires: this.now() + 60 * 60_000 }
    }
    const jwk = this.#jwks.keys.find((k) => (kid === undefined || k.kid === kid) && (k.alg === undefined || k.alg === alg) && k.use !== 'enc')
    if (jwk) return createPublicKey({ key: jwk, format: 'jwk' })
    if (refetch) {
      this.#jwks = null // the provider may have rotated its keys
      return this.#key(kid, alg, false)
    }
    throw new OidcError('no key for the ID token')
  }

  // Starts a sign-in: returns the provider URL to send the browser to, and a value for a
  // cookie that ties the answer to this browser.
  async start() {
    const config = await this.discovery()
    const time = this.now()
    for (const [state, flow] of this.#flows) {
      if (flow.expires < time || this.#flows.size >= MAX_FLOWS) this.#flows.delete(state)
    }
    const state = b64url(randomBytes(32))
    const nonce = b64url(randomBytes(32))
    const verifier = b64url(randomBytes(32))
    const browser = b64url(randomBytes(32))
    this.#flows.set(state, { nonce, verifier, browser, expires: time + FLOW_LIFETIME })
    const url = new URL(config.authorization_endpoint)
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: 'openid profile email groups',
      state,
      nonce,
      code_challenge: b64url(createHash('sha256').update(verifier).digest()),
      code_challenge_method: 'S256',
    }).toString()
    return { url: url.href, browser }
  }

  // Finishes a sign-in from the provider's redirect. Returns { sub, name, groups } or throws.
  async finish({ code, state, browser }) {
    const flow = typeof state === 'string' ? this.#flows.get(state) : undefined
    if (flow) this.#flows.delete(state)
    if (!flow || flow.expires < this.now()) throw new OidcError('sign-in expired or unknown')
    const a = Buffer.from(String(browser ?? ''))
    const b = Buffer.from(flow.browser)
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new OidcError('sign-in started in another browser')
    if (typeof code !== 'string' || code.length === 0 || code.length > 2048) throw new OidcError('no code')

    const config = await this.discovery()
    const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: this.redirectUri, code_verifier: flow.verifier })
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }
    const methods = config.token_endpoint_auth_methods_supported ?? ['client_secret_basic']
    if (this.clientSecret && methods.includes('client_secret_basic')) {
      const encode = (value) => encodeURIComponent(value)
      headers.Authorization = `Basic ${Buffer.from(`${encode(this.clientId)}:${encode(this.clientSecret)}`).toString('base64')}`
    } else {
      body.set('client_id', this.clientId)
      if (this.clientSecret) body.set('client_secret', this.clientSecret)
    }
    const tokens = await this.#json(config.token_endpoint, { method: 'POST', headers, body })
    if (typeof tokens.id_token !== 'string') throw new OidcError('no ID token')
    const claims = await this.#verifyIdToken(tokens.id_token, flow.nonce)
    const groups = Array.isArray(claims.groups) ? claims.groups.filter((g) => typeof g === 'string') : []
    if (this.allowedGroup && !groups.includes(this.allowedGroup)) throw new OidcError('not in the allowed group')
    return {
      sub: claims.sub,
      name: [claims.name, claims.preferred_username, claims.email].find((v) => typeof v === 'string' && v) ?? 'Member',
      groups,
    }
  }

  async #verifyIdToken(token, nonce) {
    const parts = token.split('.')
    if (parts.length !== 3) throw new OidcError('malformed ID token')
    let header
    let claims
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    } catch {
      throw new OidcError('malformed ID token')
    }
    const algorithm = ALGORITHMS[header.alg]
    if (!algorithm) throw new OidcError(`ID token algorithm ${header.alg} not accepted`)
    const key = await this.#key(header.kid, header.alg)
    const signature = Buffer.from(parts[2], 'base64url')
    const options = { key }
    if (algorithm.pss) Object.assign(options, { padding: 6, saltLength: 32 }) // RSA_PKCS1_PSS_PADDING
    if (algorithm.ec) options.dsaEncoding = 'ieee-p1363'
    if (!verify(algorithm.hash, Buffer.from(`${parts[0]}.${parts[1]}`), options, signature)) throw new OidcError('bad ID token signature')

    const seconds = Math.floor(this.now() / 1000)
    if (claims.iss !== this.issuer) throw new OidcError('wrong issuer')
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
    if (!audiences.includes(this.clientId)) throw new OidcError('wrong audience')
    if (audiences.length > 1 && claims.azp !== this.clientId) throw new OidcError('wrong authorized party')
    if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW < seconds) throw new OidcError('ID token expired')
    if (typeof claims.iat === 'number' && claims.iat - CLOCK_SKEW > seconds) throw new OidcError('ID token from the future')
    if (claims.nonce !== nonce) throw new OidcError('wrong nonce')
    if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255) throw new OidcError('no subject')
    return claims
  }
}
