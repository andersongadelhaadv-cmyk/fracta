export function Wordmark({ className = '' }: { className?: string }) {
  return (
    <span className={`font-mono font-semibold tracking-tight ${className}`}>
      fracta<span style={{ color: 'var(--accent)' }}>.</span>
    </span>
  )
}
