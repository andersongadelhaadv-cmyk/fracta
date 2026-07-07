import type { NextRequest } from 'next/server'
import { runMonitor, formatAlertEmail, PassiveScanner, type ScanDiff } from '@fracta/web-scan'
import { getStore } from '@/lib/scan-store'
import { sendEmail } from '@/lib/mailer'
import { SITE_URL } from '@/lib/config'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

/**
 * POST /api/monitor/run — o job de monitoramento (disparado pelo cron do GitHub Actions).
 * Re-escaneia cada assinatura ativa, compara com o último scan e ALERTA por e-mail só em
 * regressão real. PRIVADO: `Authorization: Bearer <MONITOR_TOKEN>` (404 se o token faltar).
 *
 * Dry-run por PADRÃO (`MONITOR_DRY_RUN !== '0'`): só loga o que enviaria. Ligar o envio =
 * setar `MONITOR_DRY_RUN=0` + `RESEND_API_KEY`/`MONITOR_FROM` no ambiente (v1b).
 */
function tokenOk(req: NextRequest): boolean {
  const expected = process.env.MONITOR_TOKEN
  if (!expected) return false
  const auth = req.headers.get('authorization') ?? ''
  const got = auth.startsWith('Bearer ') ? auth.slice(7) : ''
  if (got.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < expected.length; i++) diff |= got.charCodeAt(i) ^ expected.charCodeAt(i)
  return diff === 0
}

export async function POST(req: NextRequest) {
  if (!tokenOk(req)) return Response.json({ error: 'Not found' }, { status: 404 })

  // Test-send (token-gated): prova o pipe REAL (formatAlertEmail + Resend) sem depender de
  // uma regressão espontânea. `{ "test": "voce@dominio" }` → manda 1 alerta de amostra.
  let body: { test?: unknown } = {}
  try { body = await req.json() } catch { /* cron manda sem corpo */ }
  const testTo = typeof body.test === 'string' ? body.test.trim() : ''
  if (testTo) {
    const sampleDiff: ScanDiff = {
      url: 'https://exemplo.com.br/', previousGrade: 'A', currentGrade: 'D', gradeDelta: 'worsened',
      newFindings: [{ id: 'hsts', severity: 'high', title: 'HSTS ausente' } as unknown as ScanDiff['newFindings'][number]],
      resolvedFindings: [], changed: true, regressed: true,
    }
    const email = formatAlertEmail(sampleDiff, {
      reportUrl: `${SITE_URL}/r/exemplo`,
      unsubUrl: `${SITE_URL}/api/unsubscribe?token=amostra`,
    })
    try {
      await sendEmail(testTo, { ...email, subject: `[TESTE] ${email.subject}` })
      return Response.json({ ok: true, testSent: true, to: testTo }, { status: 200 })
    } catch (e) {
      return Response.json({ ok: false, testSent: false, error: (e as Error).message }, { status: 502 })
    }
  }

  const store = getStore()
  if (!store) return Response.json({ ok: false, store: 'down' }, { status: 503 })

  const subs = store.listActiveSubscriptions()
  const scanner = new PassiveScanner()
  const alerts = await runMonitor({
    listActive: () => subs,
    getLastScan: (url) => store.getCachedEntry(url, Number.MAX_SAFE_INTEGER),
    scan: (url) => scanner.scan(url),
    saveScan: (r) => store.save(r),
    markNotified: (id, sid) => store.markNotified(id, sid),
  })

  const dryRun = process.env.MONITOR_DRY_RUN !== '0'
  let sent = 0
  const errors: string[] = []
  for (const a of alerts) {
    const reportUrl = `${SITE_URL}/r/${a.shareId}`
    const unsubUrl = `${SITE_URL}/api/unsubscribe?token=${encodeURIComponent(a.subscription.unsubToken)}`
    const email = formatAlertEmail(a.diff, { reportUrl, unsubUrl })
    store.bump('monitor_alert')
    if (dryRun) {
      console.log(`[monitor][dry-run] alertaria ${a.subscription.email} — ${email.subject}`)
      continue
    }
    try {
      await sendEmail(a.subscription.email, email)
      sent++
    } catch (e) {
      errors.push(`${a.subscription.email}: ${(e as Error).message}`)
    }
  }

  return Response.json(
    { ok: true, dryRun, checked: subs.length, regressed: alerts.length, sent, errors },
    { status: 200 },
  )
}
