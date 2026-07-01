import { describe, it, expect } from 'vitest'
import { applyConfidence } from '../confidence.js'
import type { Finding } from '../types.js'

function f(partial: Partial<Finding>): Finding {
  return {
    id: 'x', runId: 'r', agent: 'A', category: 'security', severity: 'high',
    title: 't', description: 'd', recommendation: 'fix', createdAt: new Date(),
    ...partial,
  }
}

describe('applyConfidence', () => {
  it('default = high quando não declarado e localização normal', () => {
    const [r] = applyConfidence([f({ evidence: 'src/app.ts:10' })])
    expect(r.confidence).toBe('high')
  })

  it('respeita confiança declarada pelo agente (low)', () => {
    const [r] = applyConfidence([f({ confidence: 'low', evidence: 'src/app.ts:10' })])
    expect(r.confidence).toBe('low')
  })

  it('rebaixa p/ low quando localizado em arquivo de teste', () => {
    expect(applyConfidence([f({ evidence: 'src/foo.test.ts:3' })])[0].confidence).toBe('low')
    expect(applyConfidence([f({ title: 'algo em src/__tests__/x.ts:1' })])[0].confidence).toBe('low')
    expect(applyConfidence([f({ evidence: 'test/fixtures/db.sql:9' })])[0].confidence).toBe('low')
    expect(applyConfidence([f({ endpoint: '/mocks/handler.ts' })])[0].confidence).toBe('low')
  })

  it('não rebaixa arquivo de produção normal', () => {
    expect(applyConfidence([f({ evidence: 'packages/api/src/auth.ts:42' })])[0].confidence).toBe('high')
  })

  it('é puro — não muta o finding original', () => {
    const orig = f({ evidence: 'a.test.ts' })
    const [r] = applyConfidence([orig])
    expect(orig.confidence).toBeUndefined()
    expect(r).not.toBe(orig)
  })
})
