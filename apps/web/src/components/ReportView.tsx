import type { PassiveScanResult } from '@fracta/web-scan'
import { GradeRing } from './GradeRing'
import { FindingRow } from './FindingRow'
import { Honesty } from './Honesty'
import { EmailCapture } from './EmailCapture'
import { BadgeEmbed } from './BadgeEmbed'
import { ZapApiSupporter } from './ZapApiSupporter'
import { sevColor, sevLabel, sortBySeverity, severityCounts } from '@/lib/grade-ui'

function host(url: string): string {
  try { return new URL(url).host } catch { return url }
}

/** Render completo de um resultado de scan. Componente puro (SSR ou inline). */
export function ReportView({ result, shareId }: { result: PassiveScanResult; shareId?: string }) {
  const findings = sortBySeverity(result.findings)
  const counts = severityCounts(result.findings)
  const date = new Date(result.scannedAt).toLocaleString('pt-BR', { dateStyle: 'medium', timeStyle: 'short' })

  return (
    <article className="mx-auto w-full max-w-content">
      <header className="flex flex-col gap-6 rounded-md border border-border bg-surface p-6 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="font-mono text-xs uppercase tracking-wide text-faint">relatório passivo</p>
          <h1 className="mt-1 truncate font-mono text-lg text-text">{host(result.url)}</h1>
          <p className="mt-1 text-xs text-muted">analisado em {date}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {counts.length === 0 && result.verdict === 'ok' && (
              <span className="rounded px-2 py-1 font-mono text-xs text-[var(--grade-a)]" style={{ border: '1px solid var(--grade-a)33' }}>
                nenhum achado nos checks executados
              </span>
            )}
            {counts.map(({ sev, n }) => (
              <span
                key={sev}
                className="rounded px-2 py-1 font-mono text-xs"
                style={{ color: sevColor(sev), border: `1px solid ${sevColor(sev)}33`, background: `${sevColor(sev)}10` }}
              >
                {n} {sevLabel(sev)}
              </span>
            ))}
          </div>
        </div>
        <div className="shrink-0 self-center">
          <GradeRing grade={result.grade} score={result.score} />
        </div>
      </header>

      <section className="mt-4">
        <Honesty result={result} />
      </section>

      {findings.length > 0 && (
        <section className="mt-4 rounded-md border border-border bg-surface p-6">
          <h2 className="font-mono text-xs uppercase tracking-wide text-muted">achados ({findings.length})</h2>
          <ul className="mt-2">
            {findings.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </ul>
        </section>
      )}

      {shareId && result.grade && (
        <section className="mt-4">
          <BadgeEmbed shareId={shareId} grade={result.grade} />
        </section>
      )}

      <section className="mt-4">
        <EmailCapture context={shareId ? `result:${shareId}` : 'result'} />
      </section>

      <section className="mt-4">
        <ZapApiSupporter />
      </section>
    </article>
  )
}
