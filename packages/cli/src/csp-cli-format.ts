import type { CspCoverageReport } from '@fracta/verify'

/**
 * Formata o relatório de cobertura de CSP para o terminal — mesmo estilo do
 * comando `verify` (headline com ✅/⚠️ + lista de achados). Puro e testável;
 * o glue de browser fica no comando.
 */
export function formatCspCli(r: CspCoverageReport): string {
  if (r.verdict === 'inconclusive') {
    return `Cobertura de CSP de ${r.url}\n⚠️  INCONCLUSIVO (não carregou num browser real — ausência de violação ≠ CSP correta)`
  }
  const lines = [
    `Cobertura de CSP em runtime de ${r.url}`,
    `scripts: ${r.evidence.scriptsTotal} · violações capturadas: ${r.evidence.violations}`,
  ]
  const acionavel = r.findings.find(f => f.severity !== 'info')
  lines.push(acionavel ? `⚠️  ${acionavel.title}` : '✅ CSP cobre os scripts (verificado em runtime)')
  for (const f of r.findings) lines.push(`- [${f.severity}] ${f.title}`)
  return lines.join('\n')
}
