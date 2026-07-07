'use client'

import { useState } from 'react'
import Link from 'next/link'

function host(url: string): string {
  try { return new URL(url).host } catch { return url }
}

/**
 * Opt-in REAL ao monitoramento contínuo de um alvo (no relatório). Consentimento
 * explícito (checkbox) → POST /api/subscribe. Alerta por e-mail só em regressão;
 * opt-out 1-clique. Substitui a antiga captura de waitlist na página de resultado.
 */
export function MonitorOptIn({ url }: { url: string }) {
  const [email, setEmail] = useState('')
  const [consent, setConsent] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    const value = email.trim()
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) {
      setError('Informe um e-mail válido.')
      return
    }
    if (!consent) {
      setError('Marque o consentimento para assinar o monitoramento.')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: value, url, consent: true }),
      })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(d.error ?? 'Não foi possível assinar agora.')
        return
      }
      setDone(true)
    } catch {
      setError('Falha de rede. Tente novamente.')
    } finally {
      setLoading(false)
    }
  }

  if (done) {
    return (
      <div className="rounded-md border border-[var(--grade-a)]/30 bg-surface px-4 py-3 text-sm text-text">
        <span className="font-mono text-xs uppercase tracking-wide text-[var(--grade-a)]">monitorando</span>{' '}
        Vamos re-escanear <span className="font-mono text-accent">{host(url)}</span> e te avisar por e-mail <span className="text-text">se a segurança piorar</span>. Sem spam; opt-out num clique.
      </div>
    )
  }

  return (
    <div className="rounded-md border border-border bg-surface px-4 py-4">
      <p className="text-sm text-text">
        Quer que o Fracta <span className="text-text">monitore</span> <span className="font-mono text-accent">{host(url)}</span> e te avise{' '}
        <span className="text-text">se a segurança piorar</span> (nota caiu ou surgiu achado novo)?
      </p>
      <form onSubmit={onSubmit} className="mt-3 flex flex-col gap-2 sm:flex-row">
        <label htmlFor="monitor-email" className="sr-only">Seu e-mail</label>
        <input
          id="monitor-email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="voce@empresa.com.br"
          className="flex-1 rounded-md border border-border-strong bg-bg px-3 py-2 font-mono text-sm text-text placeholder:text-faint focus:border-accent focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading}
          className="rounded-md border border-border-strong px-4 py-2 text-sm text-text hover:border-accent hover:text-accent disabled:opacity-50"
        >
          {loading ? 'Assinando…' : 'Monitorar'}
        </button>
      </form>
      <label className="mt-3 flex items-start gap-2 text-[13px] leading-relaxed text-muted">
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-0.5 accent-[var(--accent)]" />
        <span>Autorizo o Fracta a me enviar e-mail <span className="text-text">apenas sobre regressões de segurança deste site</span>. Sem marketing, sem spam — cancelo num clique (LGPD).</span>
      </label>
      {error && <p role="alert" className="mt-2 text-sm text-[var(--sev-high)]">{error}</p>}
      <p className="mt-2 font-mono text-[11px] text-faint">
        Finalidade limitada · opt-out 1-clique · veja a{' '}
        <Link href="/privacidade" className="underline hover:text-accent">Política de Privacidade</Link>.
      </p>
    </div>
  )
}
