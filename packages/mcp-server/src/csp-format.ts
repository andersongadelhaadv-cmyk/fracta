import type { CspCoverageReport } from '@fracta/verify'

export function formatCspReport(r: CspCoverageReport): string {
  if (r.verdict === 'inconclusive') {
    return `Cobertura de CSP em runtime de ${r.url}\nINCONCLUSIVO (alvo não carregou num browser real — ausência de violação ≠ CSP correta)`
  }
  const csp = r.evidence.cspHeader
    ? r.evidence.cspHeader
    : r.evidence.cspReportOnlyHeader
      ? `${r.evidence.cspReportOnlyHeader} (Report-Only)`
      : '(sem CSP no documento)'
  const lines = r.findings.map(f => `- [${f.severity}] ${f.title}`)
  return (
    `Cobertura de CSP em runtime de ${r.url}\n` +
    `scripts: ${r.evidence.scriptsTotal} · violações capturadas: ${r.evidence.violations}\n` +
    `CSP: ${csp}\n\n` +
    `${lines.join('\n') || '(sem achados)'}`
  )
}
