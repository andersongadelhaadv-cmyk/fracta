/**
 * Detecção PASSIVA e CONSERVADORA de stack, a partir de sinais que o alvo já
 * expõe (headers + HTML). Serve para o HeadersAgent dar o fix EXATO (ex.: snippet
 * de `next.config.js` em vez do genérico).
 *
 * Honestidade: um fix errado é PIOR que um genérico. Por isso só afirmamos o stack
 * com sinal forte; na dúvida devolvemos `[]` (o HeadersAgent cai no fix neutro).
 * Valores alinhados ao que o HeadersAgent reconhece: nextjs | express.
 */
type HeaderBag = Record<string, string | string[] | undefined>

function headerValue(headers: HeaderBag, name: string): string {
  const target = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) return Array.isArray(v) ? v.join(' ') : (v ?? '')
  }
  return ''
}

export function detectStack(headers: HeaderBag, html: string): string[] {
  const stack = new Set<string>()
  const xpb = headerValue(headers, 'x-powered-by')

  // Next.js: header explícito OU assets servidos de /_next/ (sinal forte e específico).
  if (/next\.js/i.test(xpb) || /\/_next\/|__NEXT_DATA__/.test(html)) {
    stack.add('nextjs')
  }
  // Express: header explícito (o `X-Powered-By: Express` é o default do framework).
  if (/express/i.test(xpb)) {
    stack.add('express')
  }

  return [...stack]
}
