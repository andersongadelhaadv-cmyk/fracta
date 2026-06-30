import type { Finding } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

const PRIVACY_HINT = /privacidade|privacy|pol[ií]tica de privacidade/i

/** Sinais de banner/CMP de consentimento de cookies (best-effort, passivo). */
const CONSENT_HINT = /consentimento|aceitar cookies|gerenciar cookies|cookie[- ]?consent|onetrust|cookiebot|didomi|osano|usercentrics|\bcookie banner\b|lgpd|gdpr/i

/** Rastreadores de terceiros detectáveis no HTML (client-side). */
const TRACKERS: Array<{ name: string; re: RegExp }> = [
  { name: 'Google Analytics / Tag Manager', re: /google-analytics\.com|googletagmanager\.com|\bgtag\s*\(/i },
  { name: 'Meta Pixel (Facebook)', re: /connect\.facebook\.net|fbevents\.js|\bfbq\s*\(/i },
  { name: 'Hotjar', re: /static\.hotjar\.com|\bhj\s*\(|hotjar\.com/i },
  { name: 'TikTok Pixel', re: /analytics\.tiktok\.com|\bttq\./i },
  { name: 'LinkedIn Insight', re: /snap\.licdn\.com/i },
  { name: 'Microsoft Clarity', re: /clarity\.ms/i },
]

/** Nomes de cookies de rastreamento conhecidos (não-essenciais). */
const TRACKING_COOKIE = /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|_hj|_clck|_clsk|_tt_|_uet|IDE|MUID|personalization_id)/i

function lgpdFinding(
  saas: string,
  runId: string,
  rule: string,
  severity: Finding['severity'],
  title: string,
  description: string,
  recommendation: string,
  evidence?: string,
): Finding {
  return {
    id: stableFindingId({ saas, camada: 'compliance', rule }),
    runId,
    agent: 'LGPD-lite (beta)',
    category: 'compliance',
    camada: 'compliance',
    severity,
    title,
    description,
    recommendation,
    references: ['https://www.gov.br/lgpd'],
    createdAt: new Date(),
    ...(evidence ? { evidence } : {}),
  }
}

/**
 * Heurística LGPD-lite (BETA, best-effort, passiva — não executa JS). Três sinais:
 * 1) Ausência de link de Política de Privacidade → low (transparência, Art. 9º).
 * 2) Rastreadores de terceiros no HTML → **info (0 pts)**: passivamente não dá pra
 *    verificar consentimento, então informamos sem penalizar (honestidade — penalizar
 *    todo site com Google Analytics seria desonesto). Avisa se há/não banner de consentimento.
 * 3) Cookie de rastreamento setado no 1º acesso (via Set-Cookie, server-side) → low:
 *    observação concreta de cookie não-essencial antes de qualquer consentimento (Art. 8º).
 * Cada finding é rotulado beta e pode ser falso-positivo.
 */
export function checkLgpdLite(html: string, setCookies: string[], saas: string, runId: string): Finding[] {
  const out: Finding[] = []
  const h = html || ''

  // 1) Link de política de privacidade
  if (!PRIVACY_HINT.test(h)) {
    out.push(lgpdFinding(
      saas, runId, 'lgpd-no-privacy-link', 'low',
      'Sem link visível de Política de Privacidade (LGPD-lite, beta)',
      'Heurística beta: não encontrei menção a "política de privacidade" na página. A LGPD exige transparência sobre o tratamento de dados (Art. 9º). Pode ser falso-positivo (link em outra página).',
      'Publique e linke uma Política de Privacidade clara, com base legal e contato do encarregado (DPO).',
    ))
  }

  // 2) Rastreadores de terceiros (info — não penaliza)
  const trackers = TRACKERS.filter((t) => t.re.test(h)).map((t) => t.name)
  if (trackers.length > 0) {
    const hasConsent = CONSENT_HINT.test(h)
    out.push(lgpdFinding(
      saas, runId, 'lgpd-third-party-trackers', 'info',
      'Rastreadores de terceiros detectados (LGPD-lite, beta)',
      `Detectei rastreadores: ${trackers.join(', ')}. Sob a LGPD, rastreamento exige base legal e cookies não-essenciais exigem consentimento PRÉVIO (Art. 7º/8º). ${hasConsent ? 'Vi sinais de banner de consentimento — confirme que ele bloqueia os trackers ANTES do aceite.' : 'NÃO vi sinais de banner de consentimento na página.'} Heurística beta (não executa JS); informativo, não penaliza a nota.`,
      'Garanta um banner de consentimento que bloqueie cookies/trackers não-essenciais até o aceite, base legal documentada, e uma Política de Privacidade clara.',
      `trackers: ${trackers.join(', ')}`,
    ))
  }

  // 3) Cookie de rastreamento setado no primeiro acesso (server-side)
  const trackingCookies = setCookies
    .map((c) => c.split('=')[0]?.trim() ?? '')
    .filter((name) => name && TRACKING_COOKIE.test(name))
  if (trackingCookies.length > 0) {
    out.push(lgpdFinding(
      saas, runId, 'lgpd-tracking-cookie-precons', 'low',
      'Cookie de rastreamento no primeiro acesso (LGPD-lite, beta)',
      `O(s) cookie(s) ${trackingCookies.join(', ')} — de rastreamento — foram definidos já no primeiro acesso, antes de qualquer interação ou consentimento. A LGPD exige consentimento PRÉVIO para cookies não-essenciais (Art. 8º).`,
      'Só defina cookies não-essenciais após o consentimento explícito do usuário.',
      `Set-Cookie: ${trackingCookies.join(', ')}`,
    ))
  }

  return out
}
