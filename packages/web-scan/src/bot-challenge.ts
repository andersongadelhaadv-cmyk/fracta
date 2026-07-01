export interface ChallengeResult {
  challenged: boolean
  vendor: string | null
}

/** Marcadores de página de desafio (JS challenge / managed challenge) do Cloudflare. */
const CF_BODY =
  /just a moment\.\.\.|challenge-platform|cf-browser-verification|cf_chl_opt|_cf_chl|enable javascript and cookies to continue|checking (if the site connection is secure|your browser before)/i

/**
 * Detecta DETERMINISTICAMENTE se a resposta é um desafio de bot-management (não o
 * conteúdo real do site). Zero rede, zero IA — só status + headers + corpo. Serve
 * pra ser HONESTO: quando o site desafia o scan, não inferimos "sem política/seguro";
 * dizemos que não conseguimos ler (e que isso é um sinal de segurança do alvo).
 */
export function detectBotChallenge(
  status: number,
  headers: Record<string, string | string[] | undefined>,
  body: string,
): ChallengeResult {
  const get = (k: string): string => {
    const v = headers[k] ?? headers[k.toLowerCase()]
    return (Array.isArray(v) ? v.join(' ') : v ?? '').toString().toLowerCase()
  }
  const server = get('server')
  const b = body || ''

  // Cloudflare — header explícito de mitigação, ou marcadores de challenge no corpo.
  if (get('cf-mitigated')) return { challenged: true, vendor: 'Cloudflare' }
  if (CF_BODY.test(b) && (server.includes('cloudflare') || /cf-chl|cloudflare/i.test(b))) {
    return { challenged: true, vendor: 'Cloudflare' }
  }
  if (server.includes('cloudflare') && (status === 403 || status === 503 || status === 429) && CF_BODY.test(b)) {
    return { challenged: true, vendor: 'Cloudflare' }
  }

  // Outros bot-managers comuns (best-effort, marcadores conhecidos).
  if (/incapsula|_incap_|visid_incap|imperva/i.test(b) || server.includes('incapsula')) {
    return { challenged: true, vendor: 'Imperva Incapsula' }
  }
  if (/perimeterx|px-captcha|_pxhd|human challenge/i.test(b)) return { challenged: true, vendor: 'PerimeterX' }
  if (get('x-datadome') || /datadome/i.test(b)) return { challenged: true, vendor: 'DataDome' }

  return { challenged: false, vendor: null }
}
