// Browser half of the desktop login. Only a short-lived one-time code reaches
// the loopback URL, and an existing browser session needs an explicit click, so
// a crafted link cannot silently hand this account to whatever is on that port.
(function () {
  const params = new URLSearchParams(location.search)
  const port = Number(params.get('port'))
  const state = params.get('state') || ''
  const statusEl = document.getElementById('status')
  const continueBtn = document.getElementById('continue')
  const switchBtn = document.getElementById('switch')
  const loginBtn = document.getElementById('login')
  let handingOff = false

  const validPort = Number.isInteger(port) && port >= 1024 && port <= 65535
  const validState = /^[a-f0-9]{32}$/.test(state)
  if (!validPort || !validState) {
    statusEl.textContent = '這個連結無效,請回到懶拍重新開始。'
    return
  }

  function show(buttons) {
    continueBtn.hidden = !buttons.includes('continue')
    switchBtn.hidden = !buttons.includes('switch')
    loginBtn.hidden = !buttons.includes('login')
  }

  async function handOff(accessToken) {
    if (handingOff) return
    handingOff = true
    show([])
    statusEl.textContent = '正在回到懶拍'
    try {
      const res = await fetch('/api/desktop/exchange', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + accessToken }
      })
      if (res.status === 403) {
        statusEl.textContent = '請先到信箱點驗證連結,再回來這一頁重新整理。'
        handingOff = false
        return
      }
      if (!res.ok) throw new Error(String(res.status))
      const body = await res.json()
      const target = new URL('http://127.0.0.1:' + port + '/callback')
      target.searchParams.set('state', state)
      target.searchParams.set('code', body.code)
      location.replace(target.toString())
    } catch (err) {
      handingOff = false
      statusEl.textContent = '登入沒有成功,請再試一次。'
      show(['login'])
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

    loginBtn.addEventListener('click', () => sdk.login())
    switchBtn.addEventListener('click', async () => {
      await sdk.logout()
      statusEl.textContent = '登入後會自動回到懶拍。'
      show(['login'])
      sdk.login()
    })
    continueBtn.addEventListener('click', () => handOff(sdk.getToken()))

    // 已有的登入狀態要先確認;這裡才開始監聽,所以只有這次主動登入會自動交接
    const existing = sdk.user && sdk.getToken()
    sdk.onAuthChange((user) => {
      if (user && sdk.getToken()) handOff(sdk.getToken())
    })
    if (existing) {
      statusEl.textContent = '目前登入的是 ' + (sdk.user.email || '這個帳號')
      show(['continue', 'switch'])
      return
    }
    statusEl.textContent = '登入後會自動回到懶拍。'
    show(['login'])
    sdk.login()
  }

  start().catch(() => {
    statusEl.textContent = '載入失敗,請重新整理。'
  })
})()
