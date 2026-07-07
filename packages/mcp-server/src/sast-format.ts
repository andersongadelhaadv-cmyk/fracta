import type { Finding, Severity } from '@fracta/core'

/**
 * Formatação HONESTA de achados SAST para o MCP, consciente de CONFIANÇA.
 *
 * O motor já rebaixa p/ `confidence: 'low'` os achados de contexto FP-prone
 * (teste/fixture/exemplo e o SELF_DETECTOR: os próprios detectores do Fracta que
 * casam os padrões que caçam). Só `confidence≠low` gateia o build. Mas o display
 * antigo listava tudo por SEVERIDADE ("6 high") sem sinalizar a confiança —
 * alarmando como se fossem vulns confirmadas. Estes helpers puros consertam isso.
 */

/** Linha do achado; marca `· baixa confiança` quando o motor rebaixou (self-detection/fixture). */
export function fmtFinding(f: Pick<Finding, 'severity' | 'title' | 'confidence'>): string {
  const low = f.confidence === 'low' ? ' · baixa confiança' : ''
  return `- [${f.severity}${low}] ${f.title}`
}

/**
 * Resumo que separa os CONFIRMADOS (alta confiança — os que reprovam) da massa de
 * baixa confiança (self-detection/fixture/exemplo — só revisão). Sem isso, "6 high"
 * lê como 6 vulns quando na verdade 0 são confirmadas.
 */
export function sastConfidenceSummary(findings: Pick<Finding, 'severity' | 'confidence'>[]): string {
  const confirmed = findings.filter((f) => f.confidence !== 'low')
  const n = (s: Severity) => confirmed.filter((f) => f.severity === s).length
  const lowConf = findings.length - confirmed.length
  const conf = `alta confiança: ${n('critical')} critical · ${n('high')} high · ${n('medium')} medium`
  const low = lowConf > 0
    ? ` · +${lowConf} de baixa confiança (self-detection/fixture/exemplo — revisão, não reprovam)`
    : ''
  return conf + low
}
