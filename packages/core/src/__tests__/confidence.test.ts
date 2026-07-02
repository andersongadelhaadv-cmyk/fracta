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

  it('rebaixa p/ low achado no código dos próprios detectores do Fracta (self-detection FP, #28)', () => {
    // O STACK agent contém strings/exemplos de padrões que ele mesmo caça
    // ($queryRawUnsafe, origin: '*') no seu source — não é superfície de produção.
    expect(applyConfidence([f({ evidence: 'packages/agents/stack/src/index.ts:224 — $queryRawUnsafe' })])[0].confidence).toBe('low')
    expect(applyConfidence([f({ title: 'CORS permissivo: packages/agents/stack/src/index.ts:410' })])[0].confidence).toBe('low')
    expect(applyConfidence([f({ evidence: 'packages/agents/secrets/src/patterns.ts:9' })])[0].confidence).toBe('low')
  })

  it('não rebaixa código de produto que só contém "agents" no caminho', () => {
    // Um SaaS-alvo com um arquivo `agents.ts` legítimo NÃO é o detector do Fracta.
    expect(applyConfidence([f({ evidence: 'packages/api/src/agents.ts:42' })])[0].confidence).toBe('high')
    expect(applyConfidence([f({ evidence: 'src/agents/handler.ts:7' })])[0].confidence).toBe('high')
  })

  it('é puro — não muta o finding original', () => {
    const orig = f({ evidence: 'a.test.ts' })
    const [r] = applyConfidence([orig])
    expect(orig.confidence).toBeUndefined()
    expect(r).not.toBe(orig)
  })
})
