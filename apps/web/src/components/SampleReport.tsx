import { GradeRing } from './GradeRing'

/**
 * Amostra REAL (estática) de relatório para o herói — o produto é a demonstração.
 * Inclui de propósito uma linha "não verificado" para mostrar a honestidade.
 */
const ROWS: Array<{ label: string; state: 'ok' | 'fail' | 'na'; note: string }> = [
  { label: 'strict-transport-security', state: 'fail', note: 'ausente · high' },
  { label: 'x-content-type-options', state: 'ok', note: 'nosniff' },
  { label: 'x-frame-options', state: 'ok', note: 'SAMEORIGIN' },
  { label: 'set-cookie · Secure/HttpOnly', state: 'fail', note: 'sem flags · low' },
  { label: 'x-powered-by', state: 'fail', note: 'Express exposto · low' },
  { label: 'política de privacidade (LGPD-lite)', state: 'na', note: 'não verificado' },
]

const icon = { ok: '✓', fail: '✗', na: '○' }
const iconColor = { ok: 'var(--grade-a)', fail: 'var(--sev-high)', na: 'var(--faint)' }

export function SampleReport() {
  return (
    <div className="rounded-md border border-border bg-surface p-5 shadow-[0_0_0_1px_rgba(0,0,0,0.3)]">
      <div className="flex items-center justify-between">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-wide text-faint">amostra · relatório passivo</p>
          <p className="mt-1 font-mono text-sm text-text">api.exemplo.com.br</p>
        </div>
        <GradeRing grade="C" score={68} size={92} />
      </div>
      <ul className="mt-4 divide-y divide-border">
        {ROWS.map((r) => (
          <li key={r.label} className="flex items-center justify-between gap-3 py-2">
            <span className="flex min-w-0 items-center gap-2">
              <span className="font-mono text-sm" style={{ color: iconColor[r.state] }}>{icon[r.state]}</span>
              <span className="truncate font-mono text-xs text-muted">{r.label}</span>
            </span>
            <span className="shrink-0 font-mono text-[11px]" style={{ color: r.state === 'na' ? 'var(--faint)' : 'var(--muted)' }}>
              {r.note}
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-3 font-mono text-[11px] text-faint">
        a última linha não foi verificada — e por isso <span className="text-muted">não conta como aprovada</span>.
      </p>
    </div>
  )
}
