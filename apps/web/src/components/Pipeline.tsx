const STEPS = ['URL', 'SSRF guard', 'HEADERS · TLS · cookies · LGPD', 'nota A–F', 'link compartilhável']

/** Diagrama "como funciona" — mono, técnico, não decorativo. */
export function Pipeline() {
  return (
    <div className="overflow-x-auto">
      <div className="flex min-w-max items-center gap-2 font-mono text-xs">
        {STEPS.map((s, i) => (
          <div key={s} className="flex items-center gap-2">
            <span className="rounded border border-border bg-surface px-3 py-2 text-muted">{s}</span>
            {i < STEPS.length - 1 && <span className="text-accent">→</span>}
          </div>
        ))}
      </div>
    </div>
  )
}
