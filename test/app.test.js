const { test, before, after } = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const createAuth = require('auth-kit')
const { createApp } = require('../src/app')

const SESSION_SECRET = 'test-session-secret-long-enough'
const PAYER = 'payer@example.com'

function fakeLmu(token) {
  if (token === 'lmu-good') return { sub: 'usr_1', email: PAYER, emailVerified: true }
  if (token === 'lmu-unverified') return { sub: 'usr_3', email: PAYER, emailVerified: false }
  if (token === 'lmu-no-email') return { sub: 'usr_2', emailVerified: true }
  return null
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

let server
let base
let paygateCalls = []
let paygateHandler = () => jsonResponse(200, { active: false })
const sessions = createAuth({ secret: SESSION_SECRET })

before(async () => {
  const handler = createApp({
    sessionSecret: SESSION_SECRET,
    verifyLetMeUse: fakeLmu,
    paygateUrl: 'https://paygate.test',
    paygateToken: 'pg-token',
    planId: 'lanpai:pro:monthly',
    publicUrl: 'https://lanpai.test',
    letmeuse: { appId: 'app_test', baseUrl: 'https://lmu.test' },
    jwksStats: () => ({ keys: 1 }),
    fetchImpl: async (url, init = {}) => {
      paygateCalls = [...paygateCalls, { url: String(url), init }]
      return paygateHandler(String(url), init)
    }
  })
  server = http.createServer(handler)
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://127.0.0.1:${server.address().port}`
})

after(() => server.close())

function call(path, { method = 'GET', token } = {}) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {}
  return fetch(`${base}${path}`, { method, headers })
}

const sessionFor = (email = PAYER) => sessions.signJWT({ sub: 'usr_1', email })

test('health reports ok and jwks state', async () => {
  const res = await call('/health')
  assert.strictEqual(res.status, 200)
  assert.deepStrictEqual(await res.json(), { ok: true, jwks: { keys: 1 } })
})

function redeem(code) {
  return fetch(`${base}/api/desktop/redeem`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code })
  })
}

async function exchangeCode() {
  const res = await call('/api/desktop/exchange', { method: 'POST', token: 'lmu-good' })
  assert.strictEqual(res.status, 200)
  return (await res.json()).code
}

test('an unverified email cannot get a billing session', async () => {
  assert.strictEqual((await call('/api/desktop/exchange', { method: 'POST', token: 'lmu-unverified' })).status, 403)
})

test('the exchange response carries no session, only a code', async () => {
  const res = await call('/api/desktop/exchange', { method: 'POST', token: 'lmu-good' })
  const body = await res.json()
  assert.deepStrictEqual(Object.keys(body), ['code'])
  assert.strictEqual(sessions.verifyJWT(body.code), null)
})

test('a login code works exactly once', async () => {
  const code = await exchangeCode()
  assert.strictEqual((await redeem(code)).status, 200)
  assert.strictEqual((await redeem(code)).status, 401)
})

test('junk and missing codes are rejected', async () => {
  assert.strictEqual((await redeem('nope')).status, 401)
  assert.strictEqual((await redeem(undefined)).status, 401)
  assert.strictEqual((await redeem({ a: 1 })).status, 401)
})

test('redeeming turns a code into a long session', async () => {
  const res = await redeem(await exchangeCode())
  const { token } = await res.json()
  const claims = sessions.verifyJWT(token)
  assert.strictEqual(claims.email, PAYER)
  assert.ok(claims.exp - Date.now() > 60 * 24 * 3600 * 1000, 'session should outlive the 4h access token')
})

test('exchange rejects a bad token and a token without email', async () => {
  assert.strictEqual((await call('/api/desktop/exchange', { method: 'POST', token: 'nope' })).status, 401)
  assert.strictEqual((await call('/api/desktop/exchange', { method: 'POST' })).status, 401)
  assert.strictEqual((await call('/api/desktop/exchange', { method: 'POST', token: 'lmu-no-email' })).status, 400)
})

test('a raw LetMeUse token is not a session', async () => {
  assert.strictEqual((await call('/api/license', { token: 'lmu-good' })).status, 401)
})

test('license reads PayGate with the session email, never a caller-supplied one', async () => {
  paygateCalls = []
  paygateHandler = () => jsonResponse(200, { active: true, tier: 'pro', end_date: '2026-12-09T00:00:00.000Z' })
  const res = await call('/api/license?email=victim@example.com', { token: sessionFor() })
  assert.strictEqual(res.status, 200)
  assert.deepStrictEqual(await res.json(), { pro: true, until: '2026-12-09T00:00:00.000Z', email: PAYER })
  const url = new URL(paygateCalls[0].url)
  assert.strictEqual(url.searchParams.get('email'), PAYER)
  assert.strictEqual(url.searchParams.get('product'), 'lanpai')
})

test('license says free when PayGate says inactive', async () => {
  paygateHandler = () => jsonResponse(200, { active: false })
  const res = await call('/api/license', { token: sessionFor() })
  assert.deepStrictEqual(await res.json(), { pro: false, until: null, email: PAYER })
})

test('license returns 502 when PayGate fails so the app keeps its cached plan', async () => {
  paygateHandler = () => jsonResponse(500, {})
  assert.strictEqual((await call('/api/license', { token: sessionFor() })).status, 502)
  paygateHandler = () => {
    throw new Error('down')
  }
  assert.strictEqual((await call('/api/license', { token: sessionFor() })).status, 502)
})

test('checkout sends the bearer, plan and return url, and returns the checkout url', async () => {
  paygateCalls = []
  paygateHandler = (url) =>
    url.includes('/api/subscription/check')
      ? jsonResponse(200, { active: false })
      : jsonResponse(200, { success: true, checkout_url: 'https://paygate.test/npay/1' })
  const res = await call('/api/checkout', { method: 'POST', token: sessionFor() })
  assert.strictEqual(res.status, 200)
  assert.deepStrictEqual(await res.json(), { checkout_url: 'https://paygate.test/npay/1' })
  const sub = paygateCalls.find((c) => c.url.endsWith('/api/newebpay/subscribe'))
  assert.strictEqual(sub.init.headers.Authorization, 'Bearer pg-token')
  assert.deepStrictEqual(JSON.parse(sub.init.body), {
    email: PAYER,
    product: 'lanpai',
    plan_id: 'lanpai:pro:monthly',
    return_url: 'https://lanpai.test/thanks'
  })
})

test('checkout refuses a second subscription for an active payer', async () => {
  paygateCalls = []
  paygateHandler = () => jsonResponse(200, { active: true, end_date: '2026-12-09T00:00:00.000Z' })
  const res = await call('/api/checkout', { method: 'POST', token: sessionFor() })
  assert.strictEqual(res.status, 409)
  assert.ok(!paygateCalls.some((c) => c.url.endsWith('/api/newebpay/subscribe')))
})

test('checkout and cancel require a session', async () => {
  assert.strictEqual((await call('/api/checkout', { method: 'POST' })).status, 401)
  assert.strictEqual((await call('/api/cancel', { method: 'POST' })).status, 401)
})

test('cancel forwards the session email and product', async () => {
  paygateCalls = []
  paygateHandler = () => jsonResponse(200, { success: true })
  const res = await call('/api/cancel', { method: 'POST', token: sessionFor() })
  assert.strictEqual(res.status, 200)
  const body = JSON.parse(paygateCalls[0].init.body)
  assert.deepStrictEqual(body, { email: PAYER, product: 'lanpai' })
})

test('cancel passes through 404 when there is nothing to cancel', async () => {
  paygateHandler = () => jsonResponse(404, { error: 'none' })
  assert.strictEqual((await call('/api/cancel', { method: 'POST', token: sessionFor() })).status, 404)
})

test('config exposes only public LetMeUse fields', async () => {
  const body = await (await call('/api/config')).json()
  assert.deepStrictEqual(body, { letmeuse: { appId: 'app_test', baseUrl: 'https://lmu.test' } })
})

test('static pages are served and path traversal is not', async () => {
  const page = await call('/desktop-login')
  assert.strictEqual(page.status, 200)
  assert.match(page.headers.get('content-type'), /text\/html/)
  assert.match(page.headers.get('content-security-policy'), /default-src/)
  assert.strictEqual((await call('/thanks')).status, 200)
  assert.strictEqual((await call('/')).status, 200)
  assert.strictEqual((await call('/..%2fpackage.json')).status, 404)
  assert.strictEqual((await call('/.env')).status, 404)
})

test('unknown routes return 404 json', async () => {
  const res = await call('/api/nope')
  assert.strictEqual(res.status, 404)
})

// PayGate 的訂閱查詢要帶 token 才回答 (不然任何人都能查任何 email 有沒有付費)
test('the subscription check carries the PayGate token', async () => {
  paygateCalls = []
  paygateHandler = () => jsonResponse(200, { active: false })
  await call('/api/license', { token: sessionFor() })
  const check = paygateCalls.find((c) => c.url.includes('/api/subscription/check'))
  assert.ok(check, 'license should ask PayGate')
  assert.strictEqual(((check.init || {}).headers || {}).Authorization, 'Bearer pg-token')
})
