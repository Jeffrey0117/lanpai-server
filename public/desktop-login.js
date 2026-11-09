// Browser half of the desktop login. The session is handed only to a loopback
// address on the user's own machine, and the port is validated as a number.
(function () {
  const params = new URLSearchParams(location.search)
  const port = Number(params.get('port'))
  const state = params.get('state') || ''
  const statusEl = document.getElementById('status')
  const loginBtn = document.getElementById('login')
  let handedOff = false

  const validPort = Number.isInteger(port) && port >= 1024 && port <= 65535
  const validState = /^[a-f0-9]{32}$/.test(state)
  if (!validPort || !validState) {
    statusEl.textContent = '這個連結無效,請回到懶拍重新開始。'
    return
  }

  async function handOff(accessToken) {
    if (handedOff) return
    handedOff = true
    statusEl.textContent = '正在回到懶拍'
    loginBtn.hidden = true
    try {
      const res = await fetch('/api/desktop/exchange', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + accessToken }
      })
      if (!res.ok) throw new Error(String(res.status))
      const body = await res.json()
      const target = new URL('http://127.0.0.1:' + port + '/callback')
      target.searchParams.set('state', state)
      target.searchParams.set('token', body.token)
      location.replace(target.toString())
    } catch (err) {
      handedOff = false
      statusEl.textContent = '登入沒有成功,請再試一次。'
      loginBtn.hidden = false
    }
  }

  function waitForSdk(timeoutMs) {
    return new Promise((resolve) => {
      const started = Date.now()
      const timer = setInterval(() => {
        const sdk = window.letmeuse
        if (sdk && sdk.ready) {
          clearInterval(timer)
          resolve(sdk)
        } else if (Date.now() - started > timeoutMs) {
          clearInterval(timer)
          resolve(null)
        }
      }, 100)
    })
  }

  async function start() {
    const config = await (await fetch('/api/config')).json()
    const script = document.createElement('script')
    script.src = config.letmeuse.baseUrl + '/letmeuse.js'
    script.dataset.appId = config.letmeuse.appId
    script.dataset.theme = 'dark'
    script.dataset.locale = 'zh'
    script.dataset.mode = 'modal'
    document.head.appendChild(script)

    const sdk = await waitForSdk(8000)
    if (!sdk) {
      statusEl.textContent = '登入元件載入失敗,請重新整理。'
      return
    }
    sdk.onAuthChange((user) => {
      if (user && sdk.getToken()) handOff(sdk.getToken())
    })
    if (sdk.user && sdk.getToken()) return handOff(sdk.getToken())
    statusEl.textContent = '登入後會自動回到懶拍。'
    loginBtn.hidden = false
    loginBtn.addEventListener('click', () => sdk.login())
    sdk.login()
  }

  start().catch(() => {
    statusEl.textContent = '載入失敗,請重新整理。'
  })
})()
