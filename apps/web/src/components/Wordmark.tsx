/**
 * Marca Fracta: símbolo da FALHA (fratura que o scan revela) + "Fracta" quadrada.
 * O símbolo é vetor inline (escala com a fonte, herda as cores da marca).
 */
export function Wordmark({ className = '' }: { className?: string }) {
  return (
    <span className={`fracta-logo ${className}`}>
      <svg className="fracta-mark" viewBox="0 0 64 64" fill="none" aria-hidden focusable="false">
        <defs>
          <clipPath id="fracta-fault-clip">
            <rect x="2" y="2" width="60" height="60" rx="15" />
          </clipPath>
        </defs>
        <rect x="2" y="2" width="60" height="60" rx="15" fill="var(--surface)" />
        <g clipPath="url(#fracta-fault-clip)">
          <path d="M30 -4 L30 28 L40 34 L40 68" stroke="var(--accent)" strokeWidth="7" />
          <path d="M30 23 L21 33" stroke="var(--accent)" strokeWidth="5" />
        </g>
        <rect x="2.5" y="2.5" width="59" height="59" rx="14.5" fill="none" stroke="var(--border-strong)" strokeWidth="2" />
      </svg>
      <span className="fracta-name">Fracta</span>
    </span>
  )
}
