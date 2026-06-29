import { NextResponse, type NextRequest } from 'next/server'
import { getStore } from '@/lib/scan-store'
import { rateLimiter } from '@/lib/rate-limit'
import { getClientIp } from '@/lib/client-ip'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/

/** POST /api/email — captura opcional (sinal de demanda). Rate-limit leve + validação. */
export async function POST(req: NextRequest) {
  const ip = getClientIp(req)
  if (!rateLimiter.check(`email:${ip}`).allowed) {
    return NextResponse.json({ error: 'Muitos envios. Tente novamente em instantes.' }, { status: 429 })
  }

  let body: { email?: unknown; context?: unknown }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Corpo inválido.' }, { status: 400 })
  }

  const email = typeof body.email === 'string' ? body.email.trim() : ''
  const context = typeof body.context === 'string' ? body.context.slice(0, 64) : 'home'
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return NextResponse.json({ error: 'E-mail inválido.' }, { status: 400 })
  }

  const store = getStore()
  if (store) {
    try {
      store.saveEmail(email, context)
    } catch (e) {
      console.warn('[fracta-web] falha ao salvar email:', (e as Error).message)
    }
  }
  // Mesmo sem store, respondemos ok (não bloqueia o usuário por degradação de persistência).
  return NextResponse.json({ ok: true }, { status: 200 })
}
