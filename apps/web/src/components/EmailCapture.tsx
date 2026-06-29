'use client'

import { useState } from 'react'

/** Captura de e-mail opcional (sinal de demanda p/ monitoramento contínuo). */
export function EmailCapture({ context = 'home' }: { context?: string }) {
  const [email, setEmail] = useState('')
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
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: value, context }),
      })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(d.error ?? 'Não foi possível registrar agora.')
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
      <div className="rounded-md border border-accent/30 bg-surface px-4 py-3 text-sm text-text">
        <span className="font-mono text-xs uppercase tracking-wide text-accent">ok</span> Anotado. Avisamos quando o monitoramento contínuo abrir.
      </div>
    )
  }

  return (
    <div className="rounded-md border border-border bg-surface px-4 py-4">
      <p className="text-sm text-text">Quer ser avisado quando lançarmos <span className="text-muted">monitoramento contínuo</span> (re-scan + alerta de regressão)?</p>
      <form onSubmit={onSubmit} className="mt-3 flex flex-col gap-2 sm:flex-row">
        <label htmlFor={`email-${context}`} className="sr-only">Seu e-mail</label>
        <input
          id={`email-${context}`}
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
          {loading ? 'Enviando…' : 'Avise-me'}
        </button>
      </form>
      {error && <p role="alert" className="mt-2 text-sm text-[var(--sev-high)]">{error}</p>}
      <p className="mt-2 font-mono text-[11px] text-faint">Só para isso. Sem spam. Você pode pedir remoção quando quiser (LGPD).</p>
    </div>
  )
}
