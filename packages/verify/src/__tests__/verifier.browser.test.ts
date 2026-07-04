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

function page(html: string): Server {
  return createServer((_req, res) => { res.setHeader('content-type', 'text/html'); res.end(html) })
}
function listen(s: Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)))
}

maybe('RuntimeVerifier (browser real)', () => {
  let violador: Server, limpo: Server, pV = 0, pL = 0

  beforeAll(async () => {
    violador = page(`<html><body>oi<script>
      new Image().src='/connect.facebook.net/en_US/fbevents.js';
    </script></body></html>`)
    limpo = page(`<html><body>site limpo</body></html>`)
    pV = await listen(violador); pL = await listen(limpo)
  })
  afterAll(() => { violador.close(); limpo.close() })

  it('CONFIRMA tracker pré-consentimento na página violadora', async () => {
    const v = new RuntimeVerifier({ allowPrivateForTest: true })
    const r = await v.verifyConsent(`http://127.0.0.1:${pV}`, { timeoutMs: 8000 })
    expect(r.evidence.trackers.map(t => t.name)).toContain('Meta Pixel (Facebook)')
    expect(r.findings.some(f => f.severity === 'low' && /antes do consentimento/i.test(f.title))).toBe(true)
  }, 30000)

  it('NÃO acusa violação na página limpa', async () => {
    const v = new RuntimeVerifier({ allowPrivateForTest: true })
    const r = await v.verifyConsent(`http://127.0.0.1:${pL}`, { timeoutMs: 8000 })
    expect(r.evidence.trackers).toEqual([])
    expect(r.findings.every(f => f.severity === 'info')).toBe(true)
  }, 30000)
})
