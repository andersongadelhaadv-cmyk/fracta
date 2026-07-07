import { describe, it, expect } from 'vitest'
import { buildScorecard, classifyOwasp } from '../scorecard.js'
import type { Finding } from '@fracta/core'

function f(over: Partial<Finding>): Finding {
  return {
    id: 'x', runId: 'r', agent: 'A', category: 'security', severity: 'high',
    title: 't', description: 'd', recommendation: 'r', createdAt: new Date(), ...over,
  }
}

describe('classifyOwasp', () => {
  it('CWE-639 (IDOR) → A01 Broken Access Control', () => {
    expect(classifyOwasp(f({ references: ['https://cwe.mitre.org/data/definitions/639.html'] }))).toBe('A01')
  })
  it('token explícito A03:2021 → A03', () => {
    expect(classifyOwasp(f({ references: ['A03:2021 - Injection'] }))).toBe('A03')
  })
  it('OWASP API broken auth (0xa2) → A07', () => {
    expect(classifyOwasp(f({ references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'] }))).toBe('A07')
  })
  it('categoria deps → A06 (componentes vulneráveis)', () => {
    expect(classifyOwasp(f({ category: 'deps', references: [] }))).toBe('A06')
  })
  it('categoria compliance → bucket LGPD (fora do OWASP, honesto)', () => {
    expect(classifyOwasp(f({ category: 'compliance', references: [] }))).toBe('LGPD')
  })
  it('sem sinal → não classificado', () => {
    expect(classifyOwasp(f({ category: 'security', references: [], description: '', title: '' }))).toBe('unclassified')
  })
})

describe('buildScorecard', () => {
  it('mostra as 10 categorias OWASP (cobertura, mesmo limpas)', () => {
    const rows = buildScorecard([])
    const owaspRows = rows.filter(r => /^A\d\d$/.test(r.id))
    expect(owaspRows).toHaveLength(10)
    expect(owaspRows.every(r => r.count === 0 && r.maxSeverity === 'none')).toBe(true)
  })

  it('agrega contagem e pior severidade por categoria', () => {
    const rows = buildScorecard([
      f({ references: ['CWE-89'], severity: 'medium' }),   // A03
      f({ references: ['A03:2021'], severity: 'high' }),    // A03
      f({ references: ['CWE-639'], severity: 'critical' }), // A01
    ])
    const a03 = rows.find(r => r.id === 'A03')!
    expect(a03.count).toBe(2)
    expect(a03.maxSeverity).toBe('high')
    expect(rows.find(r => r.id === 'A01')!.maxSeverity).toBe('critical')
  })

  it('inclui LGPD e não-classificado só quando há achados', () => {
    const rows = buildScorecard([f({ category: 'compliance', references: [] })])
    expect(rows.some(r => r.id === 'LGPD' && r.count === 1)).toBe(true)
    expect(rows.some(r => r.id === 'unclassified')).toBe(false)
  })
})
