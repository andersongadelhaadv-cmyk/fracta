import { describe, it, expect } from 'vitest'
import { evaluate, evaluatePerRule, type EvalCase } from '../bench/metrics.js'

const c = (expected: string[], actual: string[]): EvalCase => ({ expected: new Set(expected), actual: new Set(actual) })

describe('evaluate (precisão/recall/F1)', () => {
  it('conta TP/FP/FN e calcula as métricas de um caso misto', () => {
    // esperado {a,b}, previsto {a,c} → tp=a, fp=c, fn=b
    const m = evaluate([c(['a', 'b'], ['a', 'c'])])
    expect(m).toMatchObject({ tp: 1, fp: 1, fn: 1 })
    expect(m.precision).toBeCloseTo(0.5)
    expect(m.recall).toBeCloseTo(0.5)
    expect(m.f1).toBeCloseTo(0.5)
  })

  it('caso perfeito → precisão/recall/F1 = 1', () => {
    const m = evaluate([c(['a'], ['a']), c([], [])])
    expect(m).toMatchObject({ tp: 1, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 })
  })

  it('false positive puro (previu algo não esperado) derruba a precisão', () => {
    const m = evaluate([c([], ['x'])]) // esperado nada, previu x
    expect(m).toMatchObject({ tp: 0, fp: 1, fn: 0 })
    expect(m.precision).toBe(0)
  })

  it('agrega sobre múltiplos casos', () => {
    const m = evaluate([c(['a'], ['a']), c(['b'], []), c(['c'], ['c', 'd'])])
    // tp: a,c=2 · fp: d=1 · fn: b=1
    expect(m).toMatchObject({ tp: 2, fp: 1, fn: 1 })
  })
})

describe('evaluatePerRule', () => {
  it('quebra as métricas por regra', () => {
    const per = evaluatePerRule([c(['a', 'b'], ['a']), c(['a'], ['a', 'b'])])
    // a: tp em ambos (2 esperados, 2 previstos) → p1 r1 · b: 1 esperado (fn) + 1 previsto (fp)
    expect(per.a).toMatchObject({ tp: 2, fp: 0, fn: 0 })
    expect(per.b).toMatchObject({ tp: 0, fp: 1, fn: 1 })
  })
})
