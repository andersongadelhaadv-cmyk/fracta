import type { Finding } from '@fracta/core'
import { sevColor, sevLabel } from '@/lib/grade-ui'

/** Renderiza a recomendação tratando cercas de código markdown (```lang … ```). */
function Recommendation({ text }: { text: string }) {
  const parts: Array<{ code: boolean; text: string }> = []
  const re = /```(?:[a-z]*)\n?([\s\S]*?)```/gi
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push({ code: false, text: text.slice(last, m.index) })
    parts.push({ code: true, text: m[1].trim() })
    last = m.index + m[0].length
  }
  if (last < text.length) parts.push({ code: false, text: text.slice(last) })

  return (
    <span>
      {parts.map((p, i) =>
        p.code ? (
          <pre key={i} className="mt-2 overflow-x-auto rounded border border-border bg-bg px-3 py-2 font-mono text-xs text-muted">
            {p.text}
          </pre>
        ) : (
          <span key={i}>{p.text.replace(/\s+/g, ' ')}</span>
        ),
      )}
    </span>
  )
}

/**
 * Uma linha de finding. Todo conteúdo derivado do alvo (title/evidence) é
 * renderizado como TEXTO — o React escapa por padrão, então headers/cookies
 * maliciosos do alvo não viram XSS.
 */
export function FindingRow({ finding }: { finding: Finding }) {
  return (
    <li className="border-t border-border py-4 first:border-t-0">
      <div className="flex items-start gap-3">
        <span
          className="mt-0.5 shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wide"
          style={{ color: sevColor(finding.severity), border: `1px solid ${sevColor(finding.severity)}33`, background: `${sevColor(finding.severity)}14` }}
        >
          {sevLabel(finding.severity)}
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-medium text-text">{finding.title}</p>
          <p className="mt-1 text-sm leading-relaxed text-muted">{finding.description}</p>
          {finding.evidence && (
            <pre className="mt-2 overflow-x-auto rounded border border-border bg-bg px-3 py-2 font-mono text-xs text-muted">
              {finding.evidence}
            </pre>
          )}
          {finding.recommendation && (
            <div className="mt-2 text-sm text-text/80">
              <span className="font-mono text-xs uppercase tracking-wide text-accent">fix</span>{' '}
              <Recommendation text={finding.recommendation} />
            </div>
          )}
        </div>
      </div>
    </li>
  )
}
