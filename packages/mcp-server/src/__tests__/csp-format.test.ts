import { describe, it, expect } from 'vitest'
import { formatCspReport } from '../csp-format.js'

const finding = {
  id: 'x', runId: 'r', agent: 'CSP-coverage (browser)', category: 'security' as const,
  severity: 'medium' as const, confidence: 'high' as const,
  title: 'Scripts bloqueados pela CSP em runtime (cobertura incompleta)',
  description: '37 de 38 script(s) foram BLOQUEADOS', recommendation: 'cubra os scripts', createdAt: new Date(),
}

describe('formatCspReport', () => {
  it('resume cobertura, contagem de scripts/violações e lista achados', () => {
    const txt = formatCspReport({
      url: 'https://exemplo.com',
      verdict: 'ok',
      findings: [finding],
      evidence: { cspHeader: "script-src 'nonce-x'", scriptsTotal: 38, violations: 37 },
      verifiedAt: '2026-07-07T00:00:00Z',
    })
    expect(txt).toMatch(/Cobertura de CSP em runtime de https:\/\/exemplo\.com/)
    expect(txt).toMatch(/38/)
    expect(txt).toMatch(/37/)
    expect(txt).toMatch(/\[medium\]/)
  })

  it('marca INCONCLUSIVO quando o alvo não carregou', () => {
    const txt = formatCspReport({
      url: 'https://x.com', verdict: 'inconclusive', findings: [],
      evidence: { scriptsTotal: 0, violations: 0 }, verifiedAt: '2026-07-07T00:00:00Z',
    })
    expect(txt).toMatch(/INCONCLUSIVO/)
  })
})
