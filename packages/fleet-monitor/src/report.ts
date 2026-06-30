import type { DomainResult, Regression } from './monitor.js'

const GRADE_EMOJI: Record<string, string> = {
  A: '🟢 A', B: '🟢 B', C: '🟡 C', D: '🟠 D', E: '🔴 E', F: '🔴 F',
}

function gradeCell(r: DomainResult): string {
  if (r.verdict === 'inconclusive') return '⚪ inconclusivo'
  return r.grade ? GRADE_EMOJI[r.grade] ?? r.grade : '—'
}

/** Relatório markdown do estado da frota + regressões. PURO, testável. */
export function buildReport(results: DomainResult[], regressions: Regression[], when: string): string {
  const lines: string[] = []
  lines.push('# Monitor da frota — segurança passiva')
  lines.push('')
  lines.push(`Scan: ${when} · ${results.length} alvos · motor passivo do Fracta (headers · TLS · cookies · LGPD)`)
  lines.push('')

  if (regressions.length) {
    lines.push(`## ⚠️ ${regressions.length} regressão(ões) detectada(s)`)
    lines.push('')
    for (const g of regressions) {
      const what = g.kind === 'grade-drop' ? `nota caiu **${g.before} → ${g.after}**` : `**${g.before} → ${g.after}**`
      lines.push(`- **${g.label}** (\`${g.domain}\`): ${what}`)
    }
    lines.push('')
  } else {
    lines.push('## ✅ Sem regressões')
    lines.push('')
  }

  lines.push('## Estado atual')
  lines.push('')
  lines.push('| Produto | Domínio | Nota | Score |')
  lines.push('| --- | --- | --- | --- |')
  for (const r of [...results].sort((a, b) => a.label.localeCompare(b.label))) {
    lines.push(`| ${r.label} | \`${r.domain}\` | ${gradeCell(r)} | ${r.score ?? '—'} |`)
  }
  lines.push('')
  return lines.join('\n')
}
