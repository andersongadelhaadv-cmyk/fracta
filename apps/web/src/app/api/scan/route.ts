import { NextResponse, type NextRequest } from 'next/server'
import { PassiveScanner, validateScanUrl, SsrfError, type PassiveScanResult } from '@fracta/web-scan'
import { getStore } from '@/lib/scan-store'
import { rateLimiter } from '@/lib/rate-limit'
import { getClientIp } from '@/lib/client-ip'
import { CACHE_TTL_MS } from '@/lib/config'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * POST /api/scan — fluxo: rate-limit por IP → SSRF guard → cache por URL →
 * PassiveScanner (HEADERS+cookies+LGPD-lite, transporte SSRF-safe) → store.
 * Honestidade: alvo inacessível volta `inconclusive` com nota null (nunca verde).
 */
export async function POST(req: NextRequest) {
  let body: { url?: unknown }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Corpo inválido (esperado JSON com { url }).' }, { status: 400 })
  }

  const input = typeof body.url === 'string' ? body.url.trim() : ''
  if (!input) {
    return NextResponse.json({ error: 'Informe uma URL para analisar.' }, { status: 400 })
  }
  if (input.length > 2048) {
    return NextResponse.json({ error: 'URL longa demais.' }, { status: 400 })
  }

  // Rate-limit por IP
  const ip = getClientIp(req)
  const rl = rateLimiter.check(ip)
  if (!rl.allowed) {
    const retryS = Math.ceil(rl.retryAfterMs / 1000)
    return NextResponse.json(
      { error: `Muitas análises deste IP. Tente novamente em ~${retryS}s.` },
      { status: 429, headers: { 'Retry-After': String(retryS) } },
    )
  }

  // SSRF guard (mensagem clara aqui; o scanner ainda revalida o IP no connect)
  let validated: URL
  try {
    validated = await validateScanUrl(input)
  } catch (e) {
    if (e instanceof SsrfError) {
      return NextResponse.json({ error: `Recusado: ${e.message}.` }, { status: 400 })
    }
    return NextResponse.json({ error: 'URL inválida.' }, { status: 400 })
  }
  const normalized = validated.toString()

  const store = getStore()

  // Cache por URL — evita re-escanear o mesmo alvo em janela curta.
  let result: PassiveScanResult | null = store?.getCached(normalized, CACHE_TTL_MS) ?? null

  if (!result) {
    try {
      result = await new PassiveScanner().scan(normalized)
    } catch (e) {
      // Pós-validação o scanner não deveria lançar (alvo inacessível vira inconclusive),
      // mas qualquer erro inesperado é honesto: nunca afirmamos "seguro".
      return NextResponse.json(
        { error: `Não foi possível concluir a análise: ${(e as Error).message}` },
        { status: 502 },
      )
    }
  }

  // Persiste (gera shareId). Se o store estiver indisponível, retorna inline.
  if (store) {
    const shareId = store.save(result)
    return NextResponse.json({ shareId, grade: result.grade, verdict: result.verdict }, { status: 200 })
  }
  return NextResponse.json({ result }, { status: 200 })
}
