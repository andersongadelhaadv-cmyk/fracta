import { describe, it, expect } from 'vitest'
import { analyzeCspCoverage, type CspCoverageInput } from '../csp-coverage.js'

const base: CspCoverageInput = {
  saas: 'exemplo.com',
  runId: 'run-1',
  cspHeader: undefined,
  scripts: [],
  violations: [],
}

describe('analyzeCspCoverage', () => {
  it('CONFIRMA em runtime scripts bloqueados por CSP estrita em enforce (o caso 37/38)', () => {
    const scripts = Array.from({ length: 38 }, (_, i) =>
      i === 0
        ? { inline: false, src: 'https://self/app.js', hasNonce: true, hasIntegrity: false }
        : { inline: true, hasNonce: false, hasIntegrity: false },
    )
    const violations = Array.from({ length: 37 }, () => ({
      violatedDirective: 'script-src-elem',
      blockedURI: 'inline',
      disposition: 'enforce' as const,
    }))
    const f = analyzeCspCoverage({
      ...base,
      cspHeader: "script-src 'nonce-abc' 'self'",
      scripts,
      violations,
    })
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('medium')
    expect(f[0].confidence).toBe('high')
    expect(f[0].agent).toBe('CSP-coverage (browser)')
    expect(f[0].title).toMatch(/bloquead|não cobert|nao cobert/i)
    // prova quantitativa: 37 de 38
    expect(f[0].description).toMatch(/37/)
    expect(f[0].description).toMatch(/38/)
    expect(f[0].references?.length).toBeGreaterThan(0)
    expect(f[0].id).toBeTruthy()
  })

  it('CSP Report-Only que bloquearia scripts vira aviso pré-enforce (low, verificado)', () => {
    const f = analyzeCspCoverage({
      ...base,
      cspReportOnlyHeader: "script-src 'nonce-x'",
      scripts: [{ inline: true, hasNonce: false, hasIntegrity: false }],
      violations: [{ violatedDirective: 'script-src', blockedURI: 'inline', disposition: 'report' }],
    })
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('low')
    expect(f[0].confidence).toBe('high')
    expect(f[0].title).toMatch(/report-only|enforce/i)
  })

  it('CSP estrita com 100% dos scripts cobertos e zero violações = info (prova positiva)', () => {
    const f = analyzeCspCoverage({
      ...base,
      cspHeader: "script-src 'nonce-abc' 'self'",
      scripts: [
        { inline: true, hasNonce: true, hasIntegrity: false },
        { inline: false, src: 'https://self/a.js', hasNonce: true, hasIntegrity: false },
      ],
      violations: [],
    })
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('info')
    expect(f[0].title).toMatch(/100%|cobre|coberto/i)
    expect(f[0].description).toMatch(/2/) // 2 scripts
  })

  it("script-src com 'unsafe-inline' = info (política não restringe scripts), calibrado baixo", () => {
    const f = analyzeCspCoverage({
      ...base,
      cspHeader: "script-src 'self' 'unsafe-inline'",
      scripts: [{ inline: true, hasNonce: false, hasIntegrity: false }],
      violations: [],
    })
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('info')
    expect(f[0].title).toMatch(/unsafe-inline|não restringe|nao restringe/i)
  })

  it('sem política de script (defer ao HEADERS agent) = nenhum finding, sem duplicar', () => {
    const f = analyzeCspCoverage({
      ...base,
      cspHeader: "img-src 'self'",
      scripts: [{ inline: true, hasNonce: false, hasIntegrity: false }],
      violations: [],
    })
    expect(f).toEqual([])
  })
})
