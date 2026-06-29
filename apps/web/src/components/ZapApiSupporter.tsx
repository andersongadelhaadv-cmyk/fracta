/** Apoiador discreto do ecossistema — NUNCA o CTA principal. */
export function ZapApiSupporter() {
  return (
    <a
      href="https://zappbot.pro"
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center justify-between gap-4 rounded-md border border-border bg-bg px-4 py-3 text-sm text-muted transition-colors hover:border-border-strong"
    >
      <span>
        <span className="font-mono text-[11px] uppercase tracking-wide text-faint">ecossistema</span>{' '}
        ZAP-API — ponte WhatsApp ↔ seu SaaS, feita por quem também construiu o Fracta.
      </span>
      <span className="shrink-0 font-mono text-xs text-accent">conhecer →</span>
    </a>
  )
}
