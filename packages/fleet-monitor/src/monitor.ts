import { PassiveScanner } from '@fracta/web-scan'
import type { ScanGrade, ScanVerdict } from '@fracta/web-scan'
import { FLEET, type FleetTarget } from './fleet.js'

export interface DomainResult {
  domain: string
  label: string
  grade: ScanGrade | null
  score: number | null
  verdict: ScanVerdict
  scannedAt: string
}

export type BaselineEntry = Pick<DomainResult, 'grade' | 'score' | 'verdict' | 'scannedAt'>
export type Baseline = Record<string, BaselineEntry>

export type RegressionKind = 'grade-drop' | 'went-inconclusive'

export interface Regression {
  domain: string
  label: string
  kind: RegressionKind
  before: string
  after: string
}

/** A é melhor (rank maior). Drop = rank atual < rank do baseline. */
const RANK: Record<ScanGrade, number> = { A: 6, B: 5, C: 4, D: 3, E: 2, F: 1 }

/**
 * Detecta regressões comparando o scan atual com o baseline (último estado conhecido).
 * PURA (sem rede) — testável. Duas classes de alerta:
 *  - grade-drop: a nota A–F piorou (ex.: A → C).
 *  - went-inconclusive: um alvo que avaliávamos ('ok') ficou inacessível ('inconclusive').
 * Melhora de nota NÃO é regressão. Alvo sem baseline (novo) é ignorado aqui.
 */
export function diffAgainstBaseline(results: DomainResult[], baseline: Baseline): Regression[] {
  const regs: Regression[] = []
  for (const r of results) {
    const base = baseline[r.domain]
    if (!base) continue
    if (r.grade && base.grade && RANK[r.grade] < RANK[base.grade]) {
      regs.push({ domain: r.domain, label: r.label, kind: 'grade-drop', before: base.grade, after: r.grade })
    } else if (base.verdict === 'ok' && r.verdict === 'inconclusive') {
      regs.push({ domain: r.domain, label: r.label, kind: 'went-inconclusive', before: 'avaliado', after: 'inacessível' })
    }
  }
  return regs
}

export function resultsToBaseline(results: DomainResult[]): Baseline {
  const b: Baseline = {}
  for (const r of results) {
    b[r.domain] = { grade: r.grade, score: r.score, verdict: r.verdict, scannedAt: r.scannedAt }
  }
  return b
}

/**
 * Baseline com CATRACA: só grava o alvo que NÃO regrediu.
 *
 * O baseline era sobrescrito com o estado ATUAL a cada run ("alerta em transição").
 * Efeito colateral grave: um alvo que caía A→C abria a issue no dia 1, mas o C era
 * gravado como o novo baseline — no dia 2 a comparação virava C-vs-C ("sem regressão")
 * e o alarme NUNCA MAIS tocava. A degradação era LAVADA para dentro do baseline, e a
 * frota ficou 7/16 degradada (2 alvos em D) em silêncio por dias.
 *
 * Segurando o último estado BOM, a regressão continua sendo detectada a cada run até
 * alguém de fato consertar — e a catraca só sobe quando o alvo melhora. É o oposto de
 * inventar verde, que é a razão de existir deste projeto.
 */
export function ratchetBaseline(results: DomainResult[], baseline: Baseline): Baseline {
  const next: Baseline = { ...baseline }
  for (const r of results) {
    const base = baseline[r.domain]
    const entry: BaselineEntry = { grade: r.grade, score: r.score, verdict: r.verdict, scannedAt: r.scannedAt }
    if (!base) {
      next[r.domain] = entry // alvo novo: entra como está
      continue
    }
    const regrediu =
      (r.grade != null && base.grade != null && RANK[r.grade] < RANK[base.grade]) ||
      (base.verdict === 'ok' && r.verdict === 'inconclusive')
    if (!regrediu) next[r.domain] = entry // melhorou ou igual → catraca sobe
    // regrediu → mantém o baseline bom; o alarme segue tocando até consertar
  }
  return next
}

/** Pool de concorrência simples — educado com os alvos e rápido o bastante. */
async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length)
  let i = 0
  async function worker(): Promise<void> {
    while (i < items.length) {
      const idx = i++
      out[idx] = await fn(items[idx])
    }
  }
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker))
  return out
}

/** Scaneia a frota passivamente. Falha de um alvo vira 'inconclusive' (nunca derruba o lote). */
export async function scanFleet(targets: FleetTarget[] = FLEET, concurrency = 4): Promise<DomainResult[]> {
  return pool(targets, concurrency, async (t) => {
    try {
      const r = await new PassiveScanner().scan(t.domain)
      return { domain: t.domain, label: t.label, grade: r.grade, score: r.score, verdict: r.verdict, scannedAt: r.scannedAt }
    } catch {
      return { domain: t.domain, label: t.label, grade: null, score: null, verdict: 'inconclusive', scannedAt: new Date().toISOString() }
    }
  })
}
