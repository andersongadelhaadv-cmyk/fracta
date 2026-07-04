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

/**
 * Resolver injetado que distingue os hosts pela STRING literal:
 *  - `localhost`  → IP público  (permitido)
 *  - `127.0.0.1`  → IP privado  (recusado — simula metadata da cloud)
 * Ambos batem no loopback no browser; a única diferença é a DECISÃO de SSRF.
 * Esse seam é o que torna o vetor testável sem DNS falso (fixtures compartilham loopback).
 */
const resolver = async (host: string): Promise<string[]> =>
  host === 'localhost' ? ['93.184.216.34'] : ['169.254.169.254']

maybe('RuntimeVerifier — SSRF por redirect 3xx (browser real)', () => {
  let attacker: Server, target: Server, clean: Server
  let pAtk = 0, pTgt = 0, pClean = 0
  let targetHits = 0, cleanHits = 0

  beforeAll(async () => {
    // Alvo "privado": registra QUALQUER request recebido (prova server-side do leak).
    target = createServer((_req, res) => { targetHits++; res.end('SEGREDO INTERNO') })
    pTgt = await listen(target)
    // Página limpa em host permitido (localhost), destino de um redirect legítimo.
    clean = createServer((_req, res) => {
      cleanHits++
      res.setHeader('content-type', 'text/html'); res.end('<html><body>ok</body></html>')
    })
    pClean = await listen(clean)
    // Host público que redireciona (302) para o alvo privado 127.0.0.1.
    attacker = createServer((req, res) => {
      res.statusCode = 302
      const dest = req.url === '/legit'
        ? `http://localhost:${pClean}/`
        : `http://127.0.0.1:${pTgt}/`
      res.setHeader('location', dest)
      res.end()
    })
    pAtk = await listen(attacker)
  })
  afterAll(() => { attacker.close(); target.close(); clean.close() })

  it('NÃO alcança o host privado alvo de um redirect 3xx (fecha o buraco do v1)', async () => {
    targetHits = 0
    const v = new RuntimeVerifier({ resolver }) // allowPrivate=false → SSRF ativa
    const r = await v.verifyConsent(`http://localhost:${pAtk}`, { timeoutMs: 8000 })
    // Prova empírica server-side: o alvo privado JAMAIS recebeu o request.
    expect(targetHits).toBe(0)
    // Veredito honesto: nunca extrai de host interno.
    expect(r.verdict).toBe('inconclusive')
  }, 45000)

  it('SEGUE redirect para host permitido (reemite o hop e processa)', async () => {
    cleanHits = 0
    const v = new RuntimeVerifier({ resolver })
    const r = await v.verifyConsent(`http://localhost:${pAtk}/legit`, { timeoutMs: 8000 })
    // O hop permitido foi reemitido e alcançado (hipótese central: fulfill(3xx) → novo request).
    expect(cleanHits).toBeGreaterThan(0)
    expect(r.verdict).toBe('ok')
  }, 45000)
})
