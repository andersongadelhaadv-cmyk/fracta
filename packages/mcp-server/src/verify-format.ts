import type { VerifyReport } from '@fracta/verify'

export function formatVerifyReport(r: VerifyReport): string {
  const head = r.verdict === 'inconclusive'
    ? 'INCONCLUSIVO (alvo não carregou — ausência ≠ conforme)'
    : `veredito: ${r.evidence.firedBeforeInteraction ? 'trackers dispararam antes do consentimento' : 'nenhum tracker pré-consentimento'}`
  const trackers = r.evidence.trackers.map(t => t.name).join(', ') || '(nenhum)'
  const lines = r.findings.map(f => `- [${f.severity}] ${f.title}`)
  return `Verificação em runtime de ${r.url}\n${head}\nTrackers observados: ${trackers}\nCMP: ${r.evidence.cmp.detected ? r.evidence.cmp.vendor : 'não detectado'}\n\n${lines.join('\n')}`
}
