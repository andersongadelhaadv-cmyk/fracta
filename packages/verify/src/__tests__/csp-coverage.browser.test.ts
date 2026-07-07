import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createServer, type Server } from 'node:http'
import { AddressInfo } from 'node:net'
import { RuntimeCspVerifier } from '../csp-coverage-verifier.js'

// Pula se o Chromium não puder ser lançado (dev sem o binário instalado).
let hasBrowser = false
try {
  const pw = await import('playwright')
  const b = await pw.chromium.launch({ headless: true })
  await b.close()
  hasBrowser = true
} catch { hasBrowser = false }
const maybe = hasBrowser ? describe : describe.skip

/** Serve HTML com um header CSP específico. */
function page(csp: string, html: string): Server {
  return createServer((_req, res) => {
    res.setHeader('content-type', 'text/html')
    res.setHeader('content-security-policy', csp)
    res.end(html)
  })
}
function listen(s: Server): Promise<number> {
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)))
}

maybe('RuntimeCspVerifier (browser real)', () => {
  // CSP estrita (nonce), mas UM <script> inline SEM o nonce → o browser bloqueia
  // e dispara securitypolicyviolation. É o caso "policy bonita, cobertura furada".
  let furado: Server, coberto: Server, pF = 0, pC = 0

  beforeAll(async () => {
    furado = page(
      "script-src 'nonce-abc123'",
      `<html><body>
        <script>window.__x=1;/* SEM nonce → BLOQUEADO */</script>
        <script nonce="abc123">window.__y=1;/* coberto */</script>
      </body></html>`,
    )
    coberto = page(
      "script-src 'nonce-abc123'",
      `<html><body>
        <script nonce="abc123">window.__y=1;/* coberto */</script>
      </body></html>`,
    )
    pF = await listen(furado); pC = await listen(coberto)
  })
  afterAll(() => { furado.close(); coberto.close() })

  it('PEGA o script não coberto pela CSP em runtime (o que "policy ok" não pegaria)', async () => {
    const v = new RuntimeCspVerifier({ allowPrivateForTest: true })
    const r = await v.verifyCoverage(`http://127.0.0.1:${pF}`, { timeoutMs: 8000 })
    expect(r.verdict).toBe('ok')
    expect(r.evidence.violations).toBeGreaterThanOrEqual(1)
    const hit = r.findings.find(f => f.severity === 'medium' && /bloquead|cobert/i.test(f.title))
    expect(hit, JSON.stringify(r.findings, null, 2)).toBeTruthy()
    expect(hit!.confidence).toBe('high') // VERIFIED em runtime
  }, 30000)

  it('CONFIRMA cobertura 100% quando todo <script> tem nonce (prova positiva, info)', async () => {
    const v = new RuntimeCspVerifier({ allowPrivateForTest: true })
    const r = await v.verifyCoverage(`http://127.0.0.1:${pC}`, { timeoutMs: 8000 })
    expect(r.evidence.violations).toBe(0)
    expect(r.findings.every(f => f.severity === 'info')).toBe(true)
    expect(r.findings.some(f => /100%|cobre/i.test(f.title))).toBe(true)
  }, 30000)
})
