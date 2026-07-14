import { describe, it, expect } from 'vitest'
import { diffAgainstBaseline, resultsToBaseline, ratchetBaseline, type Baseline, type DomainResult } from '../monitor.js'
import { buildReport } from '../report.js'

function r(domain: string, grade: DomainResult['grade'], verdict: DomainResult['verdict'] = 'ok', score = 80): DomainResult {
  return { domain, label: domain, grade, score, verdict, scannedAt: '2026-06-30T00:00:00Z' }
}

describe('diffAgainstBaseline', () => {
  it('flagra queda de nota (A → C)', () => {
    const base: Baseline = { 'x.com': { grade: 'A', score: 95, verdict: 'ok', scannedAt: '' } }
    const regs = diffAgainstBaseline([r('x.com', 'C')], base)
    expect(regs).toHaveLength(1)
    expect(regs[0]).toMatchObject({ kind: 'grade-drop', before: 'A', after: 'C' })
  })

  it('NÃO flagra melhora de nota (C → A)', () => {
    const base: Baseline = { 'x.com': { grade: 'C', score: 60, verdict: 'ok', scannedAt: '' } }
    expect(diffAgainstBaseline([r('x.com', 'A')], base)).toHaveLength(0)
  })

  it('NÃO flagra nota igual', () => {
    const base: Baseline = { 'x.com': { grade: 'B', score: 80, verdict: 'ok', scannedAt: '' } }
    expect(diffAgainstBaseline([r('x.com', 'B')], base)).toHaveLength(0)
  })

  it('flagra alvo que avaliava e virou inconclusivo (possível queda)', () => {
    const base: Baseline = { 'x.com': { grade: 'A', score: 90, verdict: 'ok', scannedAt: '' } }
    const regs = diffAgainstBaseline([r('x.com', null, 'inconclusive')], base)
    expect(regs).toHaveLength(1)
    expect(regs[0].kind).toBe('went-inconclusive')
  })

  it('ignora alvo novo (sem baseline)', () => {
    expect(diffAgainstBaseline([r('novo.com', 'D')], {})).toHaveLength(0)
  })

  it('inconclusivo→ok (recuperou) não é regressão', () => {
    const base: Baseline = { 'x.com': { grade: null, score: null, verdict: 'inconclusive', scannedAt: '' } }
    expect(diffAgainstBaseline([r('x.com', 'A')], base)).toHaveLength(0)
  })
})

describe('resultsToBaseline', () => {
  it('mapeia domínio → estado', () => {
    const b = resultsToBaseline([r('a.com', 'A'), r('b.com', 'C')])
    expect(Object.keys(b)).toEqual(['a.com', 'b.com'])
    expect(b['a.com'].grade).toBe('A')
  })
})

describe('ratchetBaseline (catraca — não lava regressão pra dentro do baseline)', () => {
  it('alvo que REGREDIU mantém o baseline BOM (senão o alarme morre no dia seguinte)', () => {
    const base: Baseline = { 'x.com': { grade: 'A', score: 95, verdict: 'ok', scannedAt: 'ontem' } }
    const next = ratchetBaseline([r('x.com', 'C', 'ok', 74)], base)
    // O bug antigo gravava 'C' aqui → no dia seguinte C-vs-C = "sem regressão" e a
    // frota ficava degradada em SILÊNCIO. A catraca segura o último estado bom.
    expect(next['x.com'].grade).toBe('A')
    expect(next['x.com'].score).toBe(95)
  })

  it('a regressão SEGUE sendo detectada no run seguinte (o alarme não morre)', () => {
    const base: Baseline = { 'x.com': { grade: 'A', score: 95, verdict: 'ok', scannedAt: '' } }
    const dia1 = ratchetBaseline([r('x.com', 'C')], base)
    const dia2 = diffAgainstBaseline([r('x.com', 'C')], dia1) // ainda quebrado no dia seguinte
    expect(dia2).toHaveLength(1)
    expect(dia2[0]).toMatchObject({ kind: 'grade-drop', before: 'A', after: 'C' })
  })

  it('alvo que MELHOROU sobe a catraca (C → A vira o novo piso)', () => {
    const base: Baseline = { 'x.com': { grade: 'C', score: 74, verdict: 'ok', scannedAt: '' } }
    const next = ratchetBaseline([r('x.com', 'A', 'ok', 97)], base)
    expect(next['x.com'].grade).toBe('A')
    expect(next['x.com'].score).toBe(97)
  })

  it('alvo NOVO entra no baseline como está', () => {
    const next = ratchetBaseline([r('novo.com', 'D')], {})
    expect(next['novo.com'].grade).toBe('D')
  })

  it('ok → inconclusivo (alvo caiu) NÃO apaga o último estado bom', () => {
    const base: Baseline = { 'x.com': { grade: 'A', score: 95, verdict: 'ok', scannedAt: '' } }
    const next = ratchetBaseline([r('x.com', null, 'inconclusive', 0)], base)
    expect(next['x.com'].grade).toBe('A')
    expect(next['x.com'].verdict).toBe('ok')
  })

  it('não perde alvos que não vieram no run atual', () => {
    const base: Baseline = { 'sumiu.com': { grade: 'A', score: 90, verdict: 'ok', scannedAt: '' } }
    const next = ratchetBaseline([r('outro.com', 'B')], base)
    expect(next['sumiu.com'].grade).toBe('A')
  })
})

describe('buildReport', () => {
  it('marca regressões e lista o estado', () => {
    const results = [r('a.com', 'A'), r('b.com', 'D')]
    const regs = diffAgainstBaseline(results, { 'b.com': { grade: 'A', score: 90, verdict: 'ok', scannedAt: '' } })
    const md = buildReport(results, regs, '2026-06-30T00:00:00Z')
    expect(md).toContain('regressão')
    expect(md).toContain('b.com')
    expect(md).toContain('| Produto |')
  })

  it('diz "sem regressões" quando limpo', () => {
    const md = buildReport([r('a.com', 'A')], [], '2026-06-30T00:00:00Z')
    expect(md).toContain('Sem regressões')
  })
})
