import { ZAP_API_URL } from '@/lib/config'

/** Produto irmão (PreviusIA) — com logo, um pouco mais de presença, mas ainda não é o CTA principal. */
export function ZapApiSupporter() {
  return (
    <a
      href={ZAP_API_URL}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center gap-4 rounded-md border border-accent/30 bg-surface px-5 py-4 transition-colors hover:border-accent/60"
    >
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/brand/zap-api-icon.png"
        alt="ZAP-API"
        width={36}
        height={36}
        className="shrink-0 rounded-md"
      />
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="font-mono text-sm font-semibold text-text">ZAP-API</span>
          <span className="font-mono text-[10px] uppercase tracking-wide text-faint">também da PreviusIA</span>
        </span>
        <span className="mt-0.5 block text-sm text-muted">
          API REST de WhatsApp para devs — primeira mensagem em minutos. Trial 7 dias grátis.
        </span>
      </span>
      <span className="shrink-0 font-mono text-xs text-accent">conhecer →</span>
    </a>
  )
}
