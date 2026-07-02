import type { Finding } from '@fracta/core'
import type { PassiveScanResult, ScanGrade } from './types.js'

/**
 * Diff entre dois scans do MESMO alvo — a base do resumo semanal por e-mail (#4).
 * Puro e determinístico. Honra o invariante de honestidade: nota nula (inconclusivo)
 * NUNCA vira regressão inventada — o delta fica `unknown`.
 */
export interface ScanDiff {
  url: string
  previousGrade: ScanGrade | null
  currentGrade: ScanGrade | null
  /** 'improved' | 'worsened' | 'same' | 'unknown' (quando alguma nota é nula). */
  gradeDelta: 'improved' | 'worsened' | 'same' | 'unknown'
  newFindings: Finding[]
  resolvedFindings: Finding[]
  /** nota mudou OU o conjunto de achados mudou. */
  changed: boolean
  /** piorou de verdade: nota caiu OU surgiram achados novos. */
  regressed: boolean
}

// A=melhor ... F=pior. Ausente = não avaliado (inconclusivo).
const GRADE_RANK: Record<ScanGrade, number> = { A: 0, B: 1, C: 2, D: 3, E: 4, F: 5 }

/** Assinatura estável de um achado: usa `id` quando há, senão `severity::title`. */
function findingKey(f: Finding): string {
  return f.id && f.id.length > 0 ? f.id : `${f.severity}::${f.title}`
}

export function diffScans(previous: PassiveScanResult, current: PassiveScanResult): ScanDiff {
  const prevKeys = new Set(previous.findings.map(findingKey))
  const currKeys = new Set(current.findings.map(findingKey))

  const newFindings = current.findings.filter(f => !prevKeys.has(findingKey(f)))
  const resolvedFindings = previous.findings.filter(f => !currKeys.has(findingKey(f)))

  let gradeDelta: ScanDiff['gradeDelta']
  if (previous.grade === null || current.grade === null) {
    gradeDelta = 'unknown'
  } else {
    const d = GRADE_RANK[current.grade] - GRADE_RANK[previous.grade]
    gradeDelta = d === 0 ? 'same' : d > 0 ? 'worsened' : 'improved'
  }

  const findingsChanged = newFindings.length > 0 || resolvedFindings.length > 0
  const changed = gradeDelta === 'worsened' || gradeDelta === 'improved' || findingsChanged
  // Regressão só quando piora medível: nota caiu OU achado novo. 'unknown' nunca regride.
  const regressed = gradeDelta === 'worsened' || newFindings.length > 0

  return {
    url: current.url,
    previousGrade: previous.grade,
    currentGrade: current.grade,
    gradeDelta,
    newFindings,
    resolvedFindings,
    changed,
    regressed,
  }
}
