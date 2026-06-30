import { ZAP_API_URL } from '@/lib/config'

/** Produto irmão (PreviusIA), discreto — NUNCA o CTA principal. */
export function ZapApiSupporter() {
  return (
    <a
      href={ZAP_API_URL}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center justify-between gap-4 rounded-md border border-border bg-bg px-4 py-3 text-sm text-muted transition-colors hover:border-border-strong"
    >
      <span>
        <span className="font-mono text-[11px] uppercase tracking-wide text-faint">também da PreviusIA</span>{' '}
        ZAP-API — instâncias de WhatsApp API para desenvolvedores.
      </span>
      <span className="shrink-0 font-mono text-xs text-accent">conhecer →</span>
    </a>
  )
}
