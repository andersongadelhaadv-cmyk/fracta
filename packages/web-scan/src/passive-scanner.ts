import { randomUUID } from 'node:crypto'
import type { Finding, ScanScope } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'
import { HeadersAgent } from '@fracta/agent-headers'
import { validateScanUrl } from './ssrf-guard.js'
import { findCookieIssues } from './cookie-check.js'
import { checkLgpdLite } from './lgpd-lite.js'
import { grade } from './grader.js'
import type { PassiveScanResult } from './types.js'

/**
 * Orquestra SÓ checks passivos (apenas GETs, zero intrusão) reusando o motor Fracta:
 * o HEADERS agent existente + cookie flags + LGPD-lite. Sempre valida SSRF em produção
 * (allowPrivateForTest só para a integração local). Honestidade: alvo inacessível →
 * veredito `inconclusive` (NUNCA verde falso).
 */
export class PassiveScanner {
  constructor(private readonly opts: { allowPrivateForTest?: boolean } = {}) {}

  async scan(input: string): Promise<PassiveScanResult> {
    const url = this.opts.allowPrivateForTest
      ? new URL(/^https?:\/\//.test(input) ? input : `https://${input}`)
      : await validateScanUrl(input)
    const saas = url.hostname
    const runId = randomUUID()

    const findings: Finding[] = []
    let reachable = false

    // 1) HEADERS agent (passivo) — reusa o motor existente. Throw (SkippedCheck) = inacessível.
    try {
      const scope = { target: { name: saas, url: url.toString(), stack: [] }, runId, depth: 'quick' } as unknown as ScanScope
      const headers = await new HeadersAgent().run(scope)
      findings.push(...headers)
      reachable = true
    } catch { /* inacessível ou skip — tratado pelo verdict */ }

    // 2) Resposta crua p/ cookies + LGPD-lite (1 GET passivo).
    try {
      const res = await new FractaHttpClient(url.toString()).request('/', { timeoutMs: 8000 })
      reachable = true
      const sc = res.headers['set-cookie'] as unknown as string[] | string | undefined
      const setCookie = Array.isArray(sc) ? sc : sc ? [sc] : []
      findings.push(...findCookieIssues(setCookie, saas, runId))
      findings.push(...checkLgpdLite(res.raw ?? '', saas, runId))
    } catch { /* idem */ }

    const verdict = reachable ? 'ok' : 'inconclusive'
    const { grade: g, score } = grade(findings)
    return {
      url: url.toString(),
      findings,
      grade: verdict === 'ok' ? g : 'F',
      score: verdict === 'ok' ? score : 0,
      verdict,
      scannedAt: new Date().toISOString(),
    }
  }
}
