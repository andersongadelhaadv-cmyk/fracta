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

  // Cache por URL — reusa o resultado E o shareId existente (sem mintar nova linha).
  const cached = store?.getCachedEntry(normalized, CACHE_TTL_MS) ?? null
  if (cached) {
    // Medição agregada: um scan foi servido (mesmo via cache) — evento, não pessoa.
    store?.bump('scan')
    store?.bump(`grade_${cached.result.grade ?? 'NA'}`)
    return NextResponse.json(
      { shareId: cached.shareId, grade: cached.result.grade, verdict: cached.result.verdict },
      { status: 200 },
    )
  }

  let result: PassiveScanResult
  try {
    result = await new PassiveScanner().scan(normalized)
  } catch {
    // Pós-validação o scanner não deveria lançar (alvo inacessível vira inconclusive);
    // qualquer erro inesperado é honesto e genérico — nunca afirmamos "seguro" nem vazamos stack.
    return NextResponse.json({ error: 'Não foi possível concluir a análise. Tente novamente.' }, { status: 502 })
  }

  // Persiste (gera shareId). Se o store estiver indisponível, retorna inline.
  if (store) {
    const shareId = store.save(result)
    store.bump('scan')
    store.bump(`grade_${result.grade ?? 'NA'}`)
    return NextResponse.json({ shareId, grade: result.grade, verdict: result.verdict }, { status: 200 })
  }
  return NextResponse.json({ result }, { status: 200 })
}
