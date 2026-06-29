import type { Finding } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

const PRIVACY_HINT = /privacidade|privacy|pol[ií]tica de privacidade/i

/** Heurística LGPD-lite (BETA, best-effort): só sinaliza ausência de link de política de privacidade. */
export function checkLgpdLite(html: string, saas: string, runId: string): Finding[] {
  if (PRIVACY_HINT.test(html)) return []
  return [{
    id: stableFindingId({ saas, camada: 'compliance', rule: 'lgpd-no-privacy-link' }),
    runId,
    agent: 'LGPD-lite (beta)',
    category: 'compliance',
    camada: 'compliance',
    severity: 'low',
    title: 'Sem link visível de Política de Privacidade (LGPD-lite, beta)',
    description: 'Heurística beta: não encontrei menção a "política de privacidade" na home. A LGPD exige transparência sobre tratamento de dados. Pode ser falso-positivo (link em outra página).',
    recommendation: 'Publique e linke uma Política de Privacidade clara, com base legal e contato do encarregado (DPO).',
    references: ['https://www.gov.br/lgpd'],
    createdAt: new Date(),
  }]
}
