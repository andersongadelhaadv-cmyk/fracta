import { NextResponse, type NextRequest } from 'next/server'
import { validateScanUrl, SsrfError, formatWelcomeEmail } from '@fracta/web-scan'
import { getStore } from '@/lib/scan-store'
import { sendEmail } from '@/lib/mailer'
import { SITE_URL } from '@/lib/config'
import { rateLimiter } from '@/lib/rate-limit'
import { getClientIp } from '@/lib/client-ip'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/

/**
 * POST /api/subscribe — opt-in EXPLÍCITO ao monitoramento contínuo de uma URL.
 * LGPD: exige `consent === true` (finalidade limitada: alerta de regressão). A URL passa
 * pelo mesmo SSRF-guard do scan (só alvos públicos). O opt-out é 1-clique (link no e-mail).
 */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req)
  if (!rateLimiter.check(`subscribe:${ip}`).allowed) {
    return NextResponse.json({ error: 'Muitos envios. Tente novamente em instantes.' }, { status: 429 })
  }

  let body: { email?: unknown; url?: unknown; consent?: unknown }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Corpo inválido.' }, { status: 400 })
  }

  const email = typeof body.email === 'string' ? body.email.trim() : ''
  const rawUrl = typeof body.url === 'string' ? body.url.trim() : ''
  const consent = body.consent === true

  if (!EMAIL_RE.test(email) || email.length > 254) {
    return NextResponse.json({ error: 'E-mail inválido.' }, { status: 400 })
  }
  if (!consent) {
    return NextResponse.json({ error: 'É preciso consentir com o monitoramento para assinar.' }, { status: 400 })
  }

  let url: string
  try {
    url = (await validateScanUrl(rawUrl)).toString()
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof SsrfError ? `Recusado: ${e.message}.` : 'URL inválida.' },
      { status: 400 },
    )
  }

  const store = getStore()
  if (store) {
    try {
      const { token } = store.subscribe(email, url)
      store.bump('monitor_subscribe')
      // Boas-vindas/confirmação (best-effort; dry-run só loga). Falha de envio não derruba a assinatura.
      const welcome = formatWelcomeEmail({
        url,
        unsubUrl: `${SITE_URL}/api/unsubscribe?token=${encodeURIComponent(token)}`,
        headerSrc: `${SITE_URL}/email/monitor-welcome.png`,
      })
      if (process.env.MONITOR_DRY_RUN !== '0') {
        console.log(`[subscribe][dry-run] welcome p/ ${email}`)
      } else {
        try { await sendEmail(email, welcome) } catch (e) { console.warn('[fracta-web] welcome falhou:', (e as Error).message) }
      }
    } catch (e) {
      console.warn('[fracta-web] falha ao assinar monitoramento:', (e as Error).message)
    }
  }
  // Degradação graciosa: mesmo sem store, não bloqueamos o usuário.
  return NextResponse.json({ ok: true }, { status: 200 })
}
