import { type NextRequest } from 'next/server'
import { getStore } from '@/lib/scan-store'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * GET /api/unsubscribe?token=… — opt-out de 1 clique (links de e-mail são GET).
 * Idempotente e sem PII na URL além do token opaco. Devolve uma página de confirmação.
 */
export function GET(req: NextRequest) {
  const token = new URL(req.url).searchParams.get('token') ?? ''
  const store = getStore()
  const ok = token && store ? store.unsubscribe(token) : false
  if (ok) store?.bump('monitor_unsubscribe')

  const msg = ok
    ? 'Pronto — você não vai mais receber alertas de monitoramento deste site.'
    : 'Assinatura não encontrada (o link pode já ter sido usado ou expirado).'
  const html = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>Fracta — monitoramento</title>
<style>body{margin:0;background:#0a0b0d;color:#e5e7eb;font-family:ui-sans-serif,system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}
.c{max-width:460px;padding:32px;text-align:center}a{color:#5eead4}code{color:#5eead4}</style></head>
<body><div class="c"><p style="font-family:ui-monospace,monospace;color:#5eead4">❯ fracta</p>
<h1 style="font-size:20px">${ok ? 'Cancelado' : 'Nada a cancelar'}</h1>
<p style="color:#9ca3af;line-height:1.6">${msg}</p>
<p><a href="https://fracta.pro">← voltar ao fracta.pro</a></p></div></body></html>`
  return new Response(html, {
    status: ok ? 200 : 404,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  })
}
