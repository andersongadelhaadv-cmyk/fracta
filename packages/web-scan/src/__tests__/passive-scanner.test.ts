import { describe, it, expect, afterAll } from 'vitest'
import http from 'node:http'
import { PassiveScanner } from '../passive-scanner.js'

const server = http.createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'sid=x' }) // sem flags + sem headers de segurança
  res.end('<html><body>sem privacidade</body></html>')
})
const base = await new Promise<string>((resolve) => {
  server.listen(0, '127.0.0.1', () => {
    const a = server.address()
    resolve(`http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}`)
  })
})
afterAll(() => server.close())

describe('PassiveScanner (integração)', () => {
  it('reúne findings passivos e grada o alvo de teste', async () => {
    // bypass do SSRF guard p/ permitir 127.0.0.1 SÓ no teste:
    const r = await new PassiveScanner({ allowPrivateForTest: true }).scan(base)
    expect(r.verdict).toBe('ok')
    expect(r.findings.length).toBeGreaterThan(0) // headers ausentes + cookie sem flags + lgpd-lite
    expect(['A', 'B', 'C', 'D', 'E', 'F']).toContain(r.grade)
    expect(r.checks.find((c) => c.name === 'security-headers')?.status).toBe('ok')
  })
  it('veredito inconclusive + nota NULL p/ alvo inacessível (nunca F falso)', async () => {
    const r = await new PassiveScanner({ allowPrivateForTest: true }).scan('http://127.0.0.1:1') // porta fechada
    expect(r.verdict).toBe('inconclusive')
    expect(r.grade).toBeNull()
    expect(r.score).toBeNull()
    expect(r.checks.find((c) => c.name === 'security-headers')?.status).toBe('skipped')
  })

  it('detecta Next.js e entrega o FIX EXATO do stack (snippet next.config) no card', async () => {
    // Alvo que se parece com Next (assets /_next/) e SEM headers de segurança.
    const nextServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<html><head><script src="/_next/static/chunks/main.js"></script></head><body>next</body></html>')
    })
    const nextBase = await new Promise<string>((resolve) => {
      nextServer.listen(0, '127.0.0.1', () => {
        const a = nextServer.address()
        resolve(`http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}`)
      })
    })
    try {
      const r = await new PassiveScanner({ allowPrivateForTest: true }).scan(nextBase)
      // Um header de segurança ausente vira finding com a recomendação stack-aware.
      const withNextFix = r.findings.some((f) => /next\.config/i.test(f.recommendation))
      expect(withNextFix).toBe(true)
    } finally {
      nextServer.close()
    }
  })
})
