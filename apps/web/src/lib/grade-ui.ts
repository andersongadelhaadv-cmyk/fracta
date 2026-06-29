import type { Finding } from '@fracta/core'
import type { ScanGrade } from '@fracta/web-scan'

/** Cor da escala semântica de nota (separada do acento de marca). */
export function gradeColor(g: ScanGrade | null): string {
  switch (g) {
    case 'A': return 'var(--grade-a)'
    case 'B': return 'var(--grade-b)'
    case 'C': return 'var(--grade-c)'
    case 'D': return 'var(--grade-d)'
    case 'E': return 'var(--grade-e)'
    case 'F': return 'var(--grade-f)'
    default: return 'var(--grade-na)'
  }
}

type Severity = Finding['severity']

export function sevColor(s: Severity): string {
  return `var(--sev-${s})`
}

export function sevLabel(s: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'Crítico',
    high: 'Alto',
    medium: 'Médio',
    low: 'Baixo',
    info: 'Info',
  }
  return map[s]
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
}

export function severityCounts(findings: Finding[]): Array<{ sev: Severity; n: number }> {
  return SEV_ORDER.map((sev) => ({ sev, n: findings.filter((f) => f.severity === sev).length })).filter((x) => x.n > 0)
}
