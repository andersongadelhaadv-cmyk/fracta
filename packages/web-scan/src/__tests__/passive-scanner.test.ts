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
})
