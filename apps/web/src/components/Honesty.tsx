import type { PassiveScanResult } from '@fracta/web-scan'

/**
 * A honestidade como UI: veredito inconclusivo e checks que não rodaram aparecem
 * explicitamente — JAMAIS como verde. "Ausência de achado não é segurança."
 */
export function Honesty({ result }: { result: PassiveScanResult }) {
  const skipped = result.checks.filter((c) => c.status === 'skipped')

  return (
    <div className="space-y-3">
      {result.verdict === 'inconclusive' && (
        <div className="rounded-md border border-[var(--grade-na)]/40 bg-surface px-4 py-3">
          <p className="font-mono text-xs uppercase tracking-wide text-faint">veredito: inconclusivo</p>
          <p className="mt-1 text-sm text-muted">
            Não conseguimos exercer o alvo (fora do ar, bloqueando, ou tempo esgotado). Isto <strong className="text-text">não</strong> quer
            dizer que está seguro — quer dizer que <strong className="text-text">não foi verificado</strong>. Por isso não há nota.
          </p>
        </div>
      )}
      {skipped.length > 0 && (
        <div className="rounded-md border border-border border-dashed bg-bg px-4 py-3">
          <p className="font-mono text-xs uppercase tracking-wide text-faint">checks não executados</p>
          <ul className="mt-1 space-y-0.5 text-sm text-muted">
            {skipped.map((c) => (
              <li key={c.name} className="font-mono text-xs">
                <span className="text-faint">○</span> {c.name} — não verificado
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
