/**
 * Métricas de correção de um detector determinístico: precisão, recall e F1 a partir de
 * conjuntos ESPERADO (ground-truth) × PREVISTO (o que o detector emitiu). Puro. Não faz
 * parte do bundle publicado (só o benchmark/testes importam daqui).
 */
export interface EvalCase {
  expected: Set<string>
  actual: Set<string>
}

export interface Metrics {
  tp: number
  fp: number
  fn: number
  precision: number
  recall: number
  f1: number
}

function toMetrics(tp: number, fp: number, fn: number): Metrics {
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp) // sem previsões → sem falso positivo
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn) // nada a achar → recall trivialmente 1
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall)
  return { tp, fp, fn, precision, recall, f1 }
}

/** Métricas micro-agregadas sobre todos os casos. */
export function evaluate(cases: EvalCase[]): Metrics {
  let tp = 0
  let fp = 0
  let fn = 0
  for (const c of cases) {
    for (const a of c.actual) c.expected.has(a) ? tp++ : fp++
    for (const e of c.expected) if (!c.actual.has(e)) fn++
  }
  return toMetrics(tp, fp, fn)
}

/** Métricas por REGRA (id) — mostra onde o detector acerta/erra. */
export function evaluatePerRule(cases: EvalCase[]): Record<string, Metrics> {
  const acc: Record<string, { tp: number; fp: number; fn: number }> = {}
  const bump = (rule: string, k: 'tp' | 'fp' | 'fn') => {
    acc[rule] ??= { tp: 0, fp: 0, fn: 0 }
    acc[rule][k]++
  }
  for (const c of cases) {
    for (const a of c.actual) bump(a, c.expected.has(a) ? 'tp' : 'fp')
    for (const e of c.expected) if (!c.actual.has(e)) bump(e, 'fn')
  }
  const out: Record<string, Metrics> = {}
  for (const [rule, { tp, fp, fn }] of Object.entries(acc)) out[rule] = toMetrics(tp, fp, fn)
  return out
}
