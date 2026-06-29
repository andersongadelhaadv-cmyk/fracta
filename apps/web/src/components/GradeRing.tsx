import type { ScanGrade } from '@fracta/web-scan'
import { gradeColor } from '@/lib/grade-ui'

/** Anel de nota A–F (SVG). Nota null (inconclusivo) → anel tracejado cinza + "—". */
export function GradeRing({ grade, score, size = 128 }: { grade: ScanGrade | null; score: number | null; size?: number }) {
  const color = gradeColor(grade)
  const stroke = 6
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const pct = score == null ? 0 : Math.max(0, Math.min(100, score)) / 100
  const inconclusive = grade == null

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border-strong)" strokeWidth={stroke} />
        {!inconclusive && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={c * (1 - pct)}
          />
        )}
        {inconclusive && (
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--grade-na)" strokeWidth={stroke} strokeDasharray="4 6" />
        )}
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-mono font-semibold leading-none" style={{ color, fontSize: size * 0.42 }}>
          {grade ?? '—'}
        </span>
        {!inconclusive && <span className="mt-1 font-mono text-xs text-muted">{score}/100</span>}
        {inconclusive && <span className="mt-1 font-mono text-[10px] uppercase tracking-wide text-faint">não avaliado</span>}
      </div>
    </div>
  )
}
