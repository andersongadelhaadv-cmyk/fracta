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

/** Âncoras do HTML — pra achar o link da Política de Privacidade. */
const ANCHOR_RE = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi

/**
 * Acha o href do link de Política de Privacidade no HTML (determinístico, sem JS).
 * Prefere href que pareça de política; cai no texto da âncora. null se não achar.
 */
export function findPrivacyHref(html: string): string | null {
  if (!html) return null
  const candidates: string[] = []
  ANCHOR_RE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = ANCHOR_RE.exec(html)) !== null) {
    const href = m[1]
    const text = m[2].replace(/<[^>]+>/g, ' ')
    if (PRIVACY_HINT.test(href) || PRIVACY_HINT.test(text)) candidates.push(href)
  }
  if (candidates.length === 0) return null
  return candidates.find((h) => /privac|politica/i.test(h)) ?? candidates[0]
}

/**
 * Disclosures que a política DEVE conter (Art. 9º/18/33/41). Checagem determinística
 * por palavras-chave (zero LLM): heurística ampla pra evitar falso "ausente".
 */
const DISCLOSURES: Array<{ label: string; re: RegExp }> = [
  { label: 'encarregado/DPO e contato', re: /encarregad|\bDPO\b|data protection officer|respons[áa]vel pela prote[çc][ãa]o de dados/i },
  { label: 'base legal do tratamento', re: /base[s]? legal|hip[óo]tese[s]? de tratamento|leg[íi]timo interesse|execu[çc][ãa]o (do|de) contrato|\bconsentimento\b|obriga[çc][ãa]o legal|art(igo)?\.?\s*7[ºo°]?/i },
  { label: 'direitos do titular (Art. 18)', re: /direitos? do[s]? titular|art(igo)?\.?\s*18|portabilidade|anonimiza[çc][ãa]o|(direito|solicitar?).{0,40}(elimina|exclus|corre[çc])/i },
  { label: 'retenção/eliminação de dados', re: /reten[çc][ãa]o|por quanto tempo|prazo.{0,30}(armazena|conserva|guard)|art(igo)?\.?\s*1[56]\b/i },
  { label: 'transferência internacional (Art. 33)', re: /transfer[êe]ncia internacional|art(igo)?\.?\s*33|cl[áa]usulas?[- ]?padr[ãa]o|standard contractual|fora do (pa[íi]s|Brasil)/i },
]

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
 * 4) Se a Política de Privacidade foi lida (`policy`), análise DETERMINÍSTICA do texto
 *    (palavras-chave, zero LLM): quais disclosures do Art. 9º/18/33/41 ela menciona ou não.
 * Cada finding é rotulado beta e pode ser falso-positivo.
 */
export function checkLgpdLite(
  html: string,
  setCookies: string[],
  saas: string,
  runId: string,
  policy?: { text: string; url: string },
  botChallenge?: { vendor: string },
): Finding[] {
  // Honestidade: se o alvo respondeu com desafio de bot-management, NÃO inferimos
  // "sem política/rastreadores" a partir da página de desafio (seria falso). Dizemos
  // a verdade — não conseguimos ler — e enquadramos como sinal de segurança do alvo.
  if (botChallenge) {
    return [lgpdFinding(
      saas, runId, 'lgpd-content-blocked', 'info',
      `Conteúdo protegido por bot-management (${botChallenge.vendor}) — leitura passiva limitada`,
      `Não consegui ler o conteúdo da página automaticamente: o ${botChallenge.vendor} respondeu ao scan com um desafio de bot. Isso é um SINAL DE SEGURANÇA do seu site, não uma falha. Consequência honesta: passivamente não dá pra verificar Política de Privacidade, rastreadores nem cookies — e os headers/TLS refletem a borda do ${botChallenge.vendor}, não necessariamente a sua origem.`,
      `Para um diagnóstico do que está atrás da proteção, rode a análise autenticada (CLI). Se quiser um scan passivo mais fiel, libere o "FractaBot" no seu bot-management.`,
    )]
  }

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

  // 4) Leitura determinística da política de privacidade (quando lida com sucesso).
  if (policy && policy.text.trim().length > 200) {
    const covered: string[] = []
    const missing: string[] = []
    for (const d of DISCLOSURES) (d.re.test(policy.text) ? covered : missing).push(d.label)
    const desc = missing.length
      ? `Li automaticamente a sua Política de Privacidade. Ela MENCIONA: ${covered.join('; ') || '—'}. NÃO encontrei menção clara a: ${missing.join('; ')}. Análise determinística por palavras-chave (Art. 9º/18/33/41), sem IA — pode ser falso-positivo se a sua política usa outra redação.`
      : `Li automaticamente a sua Política de Privacidade: ela menciona todos os itens-chave que verifico — ${covered.join('; ')}. Análise determinística por palavras-chave; não substitui revisão jurídica.`
    out.push(lgpdFinding(
      saas, runId, 'lgpd-policy-analysis', 'info',
      'Política de Privacidade analisada automaticamente (LGPD-lite, beta)',
      desc,
      missing.length
        ? 'Revise a política para cobrir explicitamente os itens não encontrados, conforme os artigos da LGPD.'
        : 'Mantenha a política coerente com o tratamento real de dados.',
      `política lida: ${policy.url}`,
    ))
  }

  return out
}
