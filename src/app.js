// Billing bridge for the desktop app. The app is open source, so the PayGate
// token lives here. The caller's email only ever comes from a verified token.
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const createAuth = require('auth-kit')
const createRateLimiter = require('ratelimit-kit')

const PRODUCT = 'lanpai'
const SESSION_MS = 90 * 24 * 3600 * 1000
const FETCH_TIMEOUT_MS = 10_000
const LOGIN_CODE_MS = 60_000
const MAX_BODY_BYTES = 4096

// Allowlist instead of a path join: nothing outside this table can be served.
const STATIC_ROUTES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/desktop-login': ['desktop-login.html', 'text/html; charset=utf-8'],
  '/desktop-login.js': ['desktop-login.js', 'text/javascript; charset=utf-8'],
  '/thanks': ['thanks.html', 'text/html; charset=utf-8'],
  '/site.css': ['site.css', 'text/css; charset=utf-8']
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify(body))
}

function bearer(req) {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '')
  return match ? match[1] : null
}

function readJsonBody(req) {
  return new Promise((resolve) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size <= MAX_BODY_BYTES) chunks.push(chunk)
    })
    req.on('end', () => {
      try {
        resolve(size <= MAX_BODY_BYTES ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {})
      } catch {
        resolve({})
      }
    })
    req.on('error', () => resolve({}))
  })
}

function contentSecurityPolicy(letmeuseUrl) {
  return [
    "default-src 'self'",
    `script-src 'self' ${letmeuseUrl}`,
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' ${letmeuseUrl}`,
    `frame-src ${letmeuseUrl}`,
    "img-src 'self' data: https:",
    "base-uri 'none'",
    "object-src 'none'"
  ].join('; ')
}

function createApp(options) {
  const { sessionSecret, verifyLetMeUse, paygateUrl, paygateToken, planId, publicUrl, letmeuse, jwksStats } = options
  const fetchImpl = options.fetchImpl || fetch
  const publicDir = options.publicDir || path.join(__dirname, '..', 'public')
  const limitPerMinute = options.rateLimitPerMinute || 120
  const sessions = createAuth({ secret: sessionSecret })
  const limiter = createRateLimiter({ windowMs: 60_000 })
  const csp = contentSecurityPolicy(letmeuse.baseUrl)
  const now = options.now || Date.now
  let loginCodes = new Map()

  const paygate = (urlPath, init = {}) =>
    fetchImpl(`${paygateUrl}${urlPath}`, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })

  const paygatePost = (urlPath, body) =>
    paygate(urlPath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${paygateToken}` },
      body: JSON.stringify(body)
    })

  async function readSubscription(email) {
    const query = new URLSearchParams({ email, product: PRODUCT })
    // PayGate 的訂閱查詢要帶 token 才回答
    const res = await paygate(`/api/subscription/check?${query}`, {
      headers: { Authorization: `Bearer ${paygateToken}` }
    })
    if (!res.ok) throw new Error(`PayGate check returned ${res.status}`)
    return res.json()
  }

  function requireSession(req, res) {
    const claims = sessions.verifyJWT(bearer(req))
    if (!claims || typeof claims.email !== 'string' || !claims.email) {
      sendJson(res, 401, { error: 'Please sign in' })
      return null
    }
    return claims
  }

  function exchange(req, res) {
    const claims = verifyLetMeUse(bearer(req))
    if (!claims) return sendJson(res, 401, { error: 'Invalid token' })
    if (typeof claims.email !== 'string' || !claims.email) {
      return sendJson(res, 400, { error: 'Account has no email' })
    }
    // 帳單跟著 email 走,所以 email 一定要驗證過,不然註冊別人的信箱就能動別人的訂閱
    if (claims.emailVerified !== true) return sendJson(res, 403, { error: 'Email not verified' })
    const live = [...loginCodes].filter(([, entry]) => entry.expiresAt > now())
    const code = crypto.randomBytes(32).toString('hex')
    loginCodes = new Map([
      ...live,
      [code, { sub: claims.sub, email: claims.email, expiresAt: now() + LOGIN_CODE_MS }]
    ])
    return sendJson(res, 200, { code })
  }

  // 網址只帶一次性的短效碼,長效 session 不會留在瀏覽器歷史紀錄裡
  async function redeem(req, res) {
    const { code } = await readJsonBody(req)
    const entry = typeof code === 'string' ? loginCodes.get(code) : null
    if (!entry || entry.expiresAt <= now()) return sendJson(res, 401, { error: 'Invalid or expired code' })
    loginCodes = new Map([...loginCodes].filter(([key]) => key !== code))
    const token = sessions.signJWT({ sub: entry.sub, email: entry.email }, SESSION_MS)
    return sendJson(res, 200, { token })
  }

  async function license(req, res) {
    const claims = requireSession(req, res)
    if (!claims) return undefined
    const sub = await readSubscription(claims.email)
    return sendJson(res, 200, {
      pro: sub.active === true,
      until: sub.active === true ? sub.end_date || null : null,
      email: claims.email
    })
  }

  async function checkout(req, res) {
    const claims = requireSession(req, res)
    if (!claims) return undefined
    const current = await readSubscription(claims.email)
    if (current.active === true) return sendJson(res, 409, { error: 'Already subscribed' })
    const upstream = await paygatePost('/api/newebpay/subscribe', {
      email: claims.email,
      product: PRODUCT,
      plan_id: planId,
      return_url: `${publicUrl}/thanks`
    })
    const data = await upstream.json().catch(() => ({}))
    if (!upstream.ok || !data.checkout_url) throw new Error(`PayGate subscribe returned ${upstream.status}`)
    return sendJson(res, 200, { checkout_url: data.checkout_url })
  }

  async function cancel(req, res) {
    const claims = requireSession(req, res)
    if (!claims) return undefined
    const upstream = await paygatePost('/api/newebpay/cancel', { email: claims.email, product: PRODUCT })
    if (upstream.status === 404) return sendJson(res, 404, { error: 'No active subscription' })
    if (!upstream.ok) throw new Error(`PayGate cancel returned ${upstream.status}`)
    return sendJson(res, 200, { success: true })
  }

  const apiRoutes = {
    'POST /api/desktop/exchange': exchange,
    'POST /api/desktop/redeem': redeem,
    'GET /api/license': license,
    'POST /api/checkout': checkout,
    'POST /api/cancel': cancel,
    'GET /api/config': (_req, res) =>
      sendJson(res, 200, { letmeuse: { appId: letmeuse.appId, baseUrl: letmeuse.baseUrl } })
  }

  function serveStatic(pathname, res) {
    const route = Object.prototype.hasOwnProperty.call(STATIC_ROUTES, pathname) ? STATIC_ROUTES[pathname] : null
    if (!route) return sendJson(res, 404, { error: 'Not found' })
    const [file, type] = route
    res.writeHead(200, { 'Content-Type': type, 'Content-Security-Policy': csp, 'X-Content-Type-Options': 'nosniff' })
    return fs.createReadStream(path.join(publicDir, file)).pipe(res)
  }

  return async function handle(req, res) {
    const pathname = new URL(req.url, 'http://local').pathname
    if (pathname === '/health') return sendJson(res, 200, { ok: true, jwks: jwksStats() })

    const handler = apiRoutes[`${req.method} ${pathname}`]
    if (!handler) return serveStatic(pathname, res)

    const ip = createRateLimiter.clientIp(req)
    if (!limiter.check(`api:${ip}`, limitPerMinute).allowed) {
      return sendJson(res, 429, { error: 'Too many requests' })
    }
    try {
      return await handler(req, res)
    } catch (err) {
      process.stderr.write(`[lanpai] ${req.method} ${pathname}: ${err.message}\n`)
      return sendJson(res, 502, { error: 'Billing service unavailable, please try again later' })
    }
  }
}

module.exports = { createApp }
