import { describe, it, expect } from 'vitest'
import { formatCspCli } from '../csp-cli-format.js'
import type { CspCoverageReport } from '@fracta/verify'

const finding = (severity: 'medium' | 'info', title: string) => ({
  id: 'x', runId: 'r', agent: 'CSP-coverage (browser)', category: 'security' as const,
  severity, confidence: 'high' as const, title, description: 'd', recommendation: 'r', createdAt: new Date(),
})

describe('formatCspCli', () => {
  it('destaca com ⚠️ quando há achado acionável (scripts bloqueados) + conta scripts/violações', () => {
    const r: CspCoverageReport = {
      url: 'https://x.com', verdict: 'ok',
      findings: [finding('medium', 'Scripts bloqueados pela CSP em runtime (cobertura incompleta)')],
      evidence: { cspHeader: "script-src 'nonce-a'", scriptsTotal: 38, violations: 37 },
      verifiedAt: '2026-07-07T00:00:00Z',
    }
    const out = formatCspCli(r)
    expect(out).toMatch(/⚠️/)
    expect(out).toMatch(/38/)
    expect(out).toMatch(/37/)
    expect(out).toMatch(/\[medium\]/)
  })

  it('mostra ✅ quando a cobertura é 100% (só info)', () => {
    const r: CspCoverageReport = {
      url: 'https://x.com', verdict: 'ok',
      findings: [finding('info', 'CSP cobre 100% dos 16 script(s) (verificado em runtime)')],
      evidence: { cspHeader: "script-src 'nonce-a'", scriptsTotal: 16, violations: 0 },
      verifiedAt: '2026-07-07T00:00:00Z',
    }
    const out = formatCspCli(r)
    expect(out).toMatch(/✅/)
    expect(out).toMatch(/16/)
  })

  it('marca INCONCLUSIVO quando o alvo não carregou', () => {
    const r: CspCoverageReport = {
      url: 'https://x.com', verdict: 'inconclusive', findings: [],
      evidence: { scriptsTotal: 0, violations: 0 }, verifiedAt: '2026-07-07T00:00:00Z',
    }
    expect(formatCspCli(r)).toMatch(/INCONCLUSIVO/)
  })
})
