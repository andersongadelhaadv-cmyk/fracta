import type { NextRequest } from 'next/server'
import { getStore } from '@/lib/scan-store'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * Funil first-party AGREGADO (scans, notas, views de relatório, badges, e-mails).
 * Só números — zero PII, IP, cookie ou fingerprint (coerente com a /privacidade).
 *
 * PRIVADO: exige `Authorization: Bearer <FRACTA_METRICS_TOKEN>`. Se o token não
 * estiver configurado no ambiente, o endpoint responde 404 (não revela existência
 * nem expõe o funil publicamente). Comparação de tamanho fixo p/ evitar timing leak.
 */
function tokenOk(req: NextRequest): boolean {
  const expected = process.env.FRACTA_METRICS_TOKEN
  if (!expected) return false // sem token configurado → endpoint desativado
  const auth = req.headers.get('authorization') ?? ''
  const got = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  if (got.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < expected.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i)
  return diff === 0
}

export function GET(req: NextRequest) {
  if (!tokenOk(req)) {
    // 404 (não 401): não revela que o endpoint existe quando o token falta/erra.
    return Response.json({ error: 'Not found' }, { status: 404 })
  }
  const store = getStore()
  if (!store) return Response.json({ ok: false, store: 'down' }, { status: 503 })
  return Response.json({ ok: true, ...store.metricsSummary() }, { status: 200 })
}
