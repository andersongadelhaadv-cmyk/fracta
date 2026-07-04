import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createServer, type Server } from 'node:http'
import { AddressInfo } from 'node:net'
import { RuntimeVerifier } from '../verifier.js'

// Pula se o Chromium não puder ser lançado (dev local sem o binário instalado).
let hasBrowser = false
try {
  const pw = await import('playwright')
  const b = await pw.chromium.launch({ headless: true })
  await b.close()
  hasBrowser = true
} catch { hasBrowser = false }
const maybe = hasBrowser ? describe : describe.skip

function listen(s: Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)))
}

// Regressão: o interceptor agora serve TODA resposta via route.fetch+fulfill.
// Este teste prova que um `Set-Cookie` do SERVIDOR ainda chega ao contexto — a
// detecção de cookies pré-consentimento (função central) não pode ser silenciada.
maybe('RuntimeVerifier — Set-Cookie do servidor sobrevive ao fulfill (browser real)', () => {
  let srv: Server, port = 0

  beforeAll(async () => {
    srv = createServer((_req, res) => {
      res.setHeader('set-cookie', '_ga=GA1.1.999; Path=/')
      res.setHeader('content-type', 'text/html')
      res.end('<html><body>ok</body></html>')
    })
    port = await listen(srv)
  })
  afterAll(() => { srv.close() })

  it('captura cookie _ga setado por header Set-Cookie', async () => {
    const v = new RuntimeVerifier({ allowPrivateForTest: true })
    const r = await v.verifyConsent(`http://127.0.0.1:${port}`, { timeoutMs: 8000 })
    expect(r.evidence.cookiesSetBeforeConsent).toContain('_ga')
  }, 45000)
})
