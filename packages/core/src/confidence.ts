import type { Finding, Confidence } from './types.js'

/**
 * Camada de VERIFICAÇÃO determinística (zero-token, zero-rede). Atribui/rebaixa a
 * confiança de cada achado por sinais de falso-positivo — sem julgar o mérito, só
 * o CONTEXTO. Achado localizado em teste/fixture/exemplo/mock não é superfície de
 * produção → confiança `low` (aparece no relatório, mas NÃO derruba o build).
 *
 * Objetivo (Fase 2): profundidade só vale com confiança. Isto separa "confirmado"
 * de "para revisão" — o que torna o relatório entregável a um auditor.
 */
const FP_PRONE =
  /(\.(test|spec|stories)\.[cm]?[jt]sx?|[\\/](tests?|__tests__|fixtures?|__fixtures__|mocks?|__mocks__|examples?|samples?|stories|e2e|cypress|playwright)[\\/]|\.(example|sample|mock|fixture)\.|[\\/](demo|seed)s?[\\/]|\.d\.ts$)/i

/** Concatena os campos que costumam carregar o caminho/localização do achado. */
function locationOf(f: Finding): string {
  return [f.title, f.evidence, f.endpoint].filter(Boolean).join(' ')
}

/**
 * Verifica e normaliza a confiança dos achados. Puro: mesma entrada → mesma saída.
 * - Respeita a confiança já declarada pelo agente (ex.: heurística conservadora = low).
 * - Sem confiança declarada → `high` (a maioria dos checks é determinística).
 * - Rebaixa p/ `low` se a localização casar padrões de FP (teste/fixture/exemplo).
 */
export function applyConfidence(findings: Finding[]): Finding[] {
  return findings.map((f) => {
    let confidence: Confidence = f.confidence ?? 'high'
    if (confidence !== 'low' && FP_PRONE.test(locationOf(f))) confidence = 'low'
    return confidence === f.confidence ? f : { ...f, confidence }
  })
}
