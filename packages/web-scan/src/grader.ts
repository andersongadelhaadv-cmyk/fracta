import type { Finding } from '@fracta/core'
import type { ScanGrade } from './types.js'

const WEIGHT: Record<Finding['severity'], number> = {
  critical: 35, high: 20, medium: 10, low: 3, info: 0,
}

/** Determinístico: 100 menos o peso de cada finding, clampado a [0,100], mapeado p/ letra. */
export function grade(findings: Finding[]): { grade: ScanGrade; score: number } {
  const lost = findings.reduce((s, f) => s + (WEIGHT[f.severity] ?? 0), 0)
  const score = Math.max(0, Math.min(100, 100 - lost))
  const grade: ScanGrade =
    score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : score >= 20 ? 'E' : 'F'
  return { grade, score }
}
