/** A escada: o scan passivo é o lite; o diagnóstico completo (16 dimensões) é a oferta. Discreto. */
export function LgpdFullOffer() {
  return (
    <a
      href="mailto:contato@previusia.com.br?subject=Diagn%C3%B3stico%20completo%20de%20adequa%C3%A7%C3%A3o%20%C3%A0%20LGPD"
      className="flex items-center justify-between gap-4 rounded-md border border-accent/30 bg-surface px-4 py-3 text-sm text-muted transition-colors hover:border-accent/60"
    >
      <span>
        <span className="font-mono text-[11px] uppercase tracking-wide text-accent">LGPD completo</span>{' '}
        Este é o check <span className="text-text">passivo (lite)</span>. Quer o diagnóstico de adequação nas{' '}
        <span className="text-text">16 dimensões</span> da LGPD — com ROPA, relatório e planilha de gaps? Feito por quem é advogado.
      </span>
      <span className="shrink-0 font-mono text-xs text-accent">falar com a gente →</span>
    </a>
  )
}
