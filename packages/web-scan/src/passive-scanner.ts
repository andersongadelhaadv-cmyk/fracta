import { randomUUID } from 'node:crypto'
import type { Finding, ScanScope } from '@fracta/core'
import { HeadersAgent } from '@fracta/agent-headers'
import { validateScanUrl } from './ssrf-guard.js'
import { createSafeClient } from './safe-fetch.js'
import { findCookieIssues } from './cookie-check.js'
import { checkLgpdLite } from './lgpd-lite.js'
import { grade } from './grader.js'
import type { PassiveScanResult, ScanCheck, ScanGrade, ScanVerdict } from './types.js'

/**
 * Orquestra SÓ checks passivos (apenas GETs, zero intrusão) reusando o motor Fracta:
 * o HEADERS agent existente + cookie flags + LGPD-lite. Todo fetch passa por um
 * cliente endurecido cujo dispatcher valida o IP em CADA conexão (fecha SSRF por
 * redirect e DNS rebinding). Honestidade: só emite nota se o check primário rodou;
 * alvo inacessível → veredito `inconclusive` com nota `null` (NUNCA 'F' nem verde falso).
 */
export class PassiveScanner {
  constructor(private readonly opts: { allowPrivateForTest?: boolean } = {}) {
    // Blindagem: o bypass de SSRF para fixtures locais NUNCA pode ser ligado fora de teste.
    if (opts.allowPrivateForTest && process.env.NODE_ENV !== 'test') {
      throw new Error('allowPrivateForTest só é permitido em ambiente de teste (NODE_ENV=test)')
    }
  }

  async scan(input: string): Promise<PassiveScanResult> {
    const allowPrivate = !!this.opts.allowPrivateForTest
    // Produção SEMPRE valida SSRF antes de tocar a rede. allowPrivate só p/ fixture local.
    const url = allowPrivate
      ? new URL(/^https?:\/\//.test(input) ? input : `https://${input}`)
      : await validateScanUrl(input)
    const saas = url.hostname
    const runId = randomUUID()
    const createClient = createSafeClient(allowPrivate)

    const findings: Finding[] = []
    let headersRan = false
    let contentRan = false

    // 1) HEADERS agent (passivo) — reusa o motor, transporte endurecido injetado.
    try {
      const scope: ScanScope = {
        target: { name: saas, url: url.toString(), stack: [] },
        depth: 'quick',
        agents: ['HEADERS Agent'],
        runId,
        startedAt: new Date(),
      }
      findings.push(...(await new HeadersAgent({ createClient }).run(scope)))
      headersRan = true
    } catch { /* inacessível ou skip — tratado pelo verdict honesto */ }

    // 2) Resposta crua p/ cookies + LGPD-lite (1 GET passivo).
    try {
      const res = await createClient(url.toString()).request('/', { timeoutMs: 8000 })
      contentRan = true
      const sc = res.headers['set-cookie'] as unknown as string[] | string | undefined
      const setCookie = Array.isArray(sc) ? sc : sc ? [sc] : []
      findings.push(...findCookieIssues(setCookie, saas, runId))
      findings.push(...checkLgpdLite(res.raw ?? '', setCookie, saas, runId))
    } catch { /* idem */ }

    const checks: ScanCheck[] = [
      { name: 'security-headers', status: headersRan ? 'ok' : 'skipped' },
      { name: 'cookies+lgpd', status: contentRan ? 'ok' : 'skipped' },
    ]

    // Honestidade (H2/H3): a nota só sai se o check PRIMÁRIO (headers) rodou — senão
    // estaríamos gradando sobre um subconjunto e chamando ausência de "seguro". Alvo
    // não avaliável → inconclusive + nota null (jamais 'F', que leria como "inseguro").
    const graded = headersRan
    const verdict: ScanVerdict = graded ? 'ok' : 'inconclusive'
    const g: { grade: ScanGrade | null; score: number | null } = graded
      ? grade(findings)
      : { grade: null, score: null }

    return {
      url: url.toString(),
      findings,
      grade: g.grade,
      score: g.score,
      verdict,
      checks,
      scannedAt: new Date().toISOString(),
    }
  }
}
