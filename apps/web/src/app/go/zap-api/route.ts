import { type NextRequest } from 'next/server'
import { getStore } from '@/lib/scan-store'
import { ZAP_API_DESTINO } from '@/lib/config'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * GET /go/zap-api — saída medida do CTA cross-promo.
 *
 * Existe para dar o DENOMINADOR que faltava: o `utm_source=fracta` conta quem CHEGA
 * no ZAP-API, mas ninguém contava quantos cliques saem daqui. Sem os dois lados não
 * dá para dizer se o cross-sell converte.
 *
 * Só um contador agregado por dia (`zapapi_click`), como todo o resto do funil —
 * zero cookie, zero IP, zero fingerprint. Coerente com /privacidade.
 *
 * Não dava para chamar `bump()` no componente: ZapApiSupporter também renderiza
 * dentro do ScanForm (`'use client'`) e o store é `server-only` — quebraria o build.
 */
export function GET(req: NextRequest) {
  // Só conta navegação de gente. Navegador manda Sec-Fetch-Mode: navigate ao seguir
  // um link; crawler e pré-fetch de link-preview normalmente não mandam. O redirect
  // acontece SEMPRE — o filtro decide apenas se o clique entra na contagem, para o
  // número não inflar sozinho e mentir para o lado do denominador.
  const mode = req.headers.get('sec-fetch-mode')
  if (mode === 'navigate') getStore()?.bump('zapapi_click')

  return new Response(null, {
    status: 302,
    headers: {
      location: ZAP_API_DESTINO,
      // Sem no-store o 302 é cacheado pela borda/navegador e o contador congela:
      // os cliques seguintes nunca mais chegam aqui.
      'cache-control': 'no-store, max-age=0',
      // Não queremos o redirect indexado nem seguido por crawler.
      'x-robots-tag': 'noindex, nofollow',
    },
  })
}
