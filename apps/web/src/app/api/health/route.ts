import { getStore } from '@/lib/scan-store'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * Healthcheck PROFUNDO: 200 só quando a persistência (SQLite store) está de pé.
 * Se o store degradou (node:sqlite indisponível ou /data não-gravável) → 503,
 * para o deploy CATCHAR a regressão (a home `/` passaria mesmo com store quebrado).
 */
export function GET() {
  try {
    const store = getStore()
    if (store !== null) {
      return Response.json({ ok: true, store: 'up' }, { status: 200 })
    }
    return Response.json({ ok: false, store: 'down' }, { status: 503 })
  } catch {
    return Response.json({ ok: false, store: 'error' }, { status: 503 })
  }
}
