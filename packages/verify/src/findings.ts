import type { Finding } from '@fracta/core'
import { stableFindingId } from '@fracta/core'
import type { TrackerHit } from './trackers.js'
import type { CmpDetection } from './cmp.js'

export interface BuildInput {
  saas: string
  runId: string
  trackers: TrackerHit[]
  cookiesBeforeConsent: string[]
  cmp: CmpDetection
}

/**
 * Traduz a observação de runtime em achados CONFIRMADOS. Regra: qualquer tracker
 * na captura JÁ disparou antes de qualquer interação (só capturamos o pré-consentimento).
 * A presença de CMP só refina a mensagem — não anula a violação.
 */
export function buildVerifyFindings(input: BuildInput): Finding[] {
  const { saas, runId, trackers, cookiesBeforeConsent, cmp } = input
  if (trackers.length === 0) {
    // Postura OK confirmada — info, não penaliza.
    return [{
      id: stableFindingId({ saas, camada: 'compliance', rule: 'lgpd-trackers-precons.verified-clean' }),
      runId,
      agent: 'Runtime-verify (browser)',
      category: 'compliance',
      camada: 'compliance',
      severity: 'info',
      confidence: 'high',
      title: 'Nenhum tracker disparou antes do consentimento (verificado em runtime)',
      description: `Carreguei a página num browser real e NÃO observei trackers de terceiros disparando antes de qualquer interação${cmp.detected ? ` (CMP detectado: ${cmp.vendor})` : ''}. Postura de consentimento OK para o que é verificável passivamente.`,
      recommendation: 'Mantenha o bloqueio de trackers não-essenciais até o consentimento.',
      references: ['https://www.gov.br/lgpd'],
      createdAt: new Date(),
    }]
  }

  const trackerNames = trackers.map(t => t.name).join(', ')
  const reqs = trackers.flatMap(t => t.requests).slice(0, 8)
  const cmpClause = cmp.detected
    ? `Há um CMP na página (${cmp.vendor}), mas ele NÃO bloqueia: os trackers dispararam mesmo assim.`
    : `Nenhum CMP/banner de consentimento foi detectado na página.`

  return [{
    id: stableFindingId({ saas, camada: 'compliance', rule: 'lgpd-third-party-trackers.verified' }),
    runId,
    agent: 'Runtime-verify (browser)',
    category: 'compliance',
    camada: 'compliance',
    severity: 'low',
    confidence: 'high',
    title: 'Trackers disparam ANTES do consentimento (confirmado em runtime)',
    description: `Verificado em browser real: ${trackerNames} disparou antes de qualquer interação de consentimento. ${cmpClause} A LGPD exige consentimento PRÉVIO para cookies/trackers não-essenciais (Art. 7º/8º).`,
    recommendation: 'Só carregue GA/Pixel/etc. após o consentimento explícito (bloqueie por padrão; use um CMP que realmente gateie os scripts).',
    evidence: `requisições: ${reqs.join(' | ')}${cookiesBeforeConsent.length ? `\ncookies antes do aceite: ${cookiesBeforeConsent.join(', ')}` : ''}\nCMP: ${cmp.detected ? cmp.vendor : 'não detectado'}`,
    references: ['https://www.gov.br/lgpd'],
    createdAt: new Date(),
  }]
}
