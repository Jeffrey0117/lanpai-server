const http = require('node:http')
const path = require('node:path')
const { createLetMeUseVerifier } = require('jwks-verify-kit')
const { loadEnv } = require('./src/env')
const { createApp } = require('./src/app')

loadEnv(__dirname)

function required(name) {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is not configured`)
  return value
}

async function main() {
  const appId = required('LETMEUSE_APP_ID')
  const baseUrl = required('LETMEUSE_BASE_URL')
  const verifier = createLetMeUseVerifier({
    appId,
    baseUrl,
    onError: (err) => process.stderr.write(`[jwks] ${err.message}\n`)
  })
  const stats = await verifier.ready()
  if (!stats.keys) process.stderr.write(`[boot] JWKS has no keys, logins will fail: ${stats.lastError}\n`)

  const handler = createApp({
    sessionSecret: required('SESSION_SECRET'),
    verifyLetMeUse: (token) => verifier.verifySync(token),
    paygateUrl: required('PAYGATE_URL').replace(/\/$/, ''),
    paygateToken: required('PAYGATE_TOKEN'),
    planId: process.env.LANPAI_PLAN_ID || 'lanpai:pro:monthly',
    publicUrl: required('PUBLIC_URL').replace(/\/$/, ''),
    letmeuse: { appId, baseUrl },
    jwksStats: () => verifier.stats(),
    publicDir: path.join(__dirname, 'public')
  })

  const port = Number(process.env.PORT) || 4057
  http.createServer(handler).listen(port, () => {
    process.stdout.write(`lanpai-server listening on ${port}\n`)
  })
}

main().catch((err) => {
  process.stderr.write(`[boot] ${err.message}\n`)
  process.exit(1)
})
