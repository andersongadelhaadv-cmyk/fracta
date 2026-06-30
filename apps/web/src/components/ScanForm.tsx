'use client'

import { useState, useRef } from 'react'
import { useRouter } from 'next/navigation'
import type { PassiveScanResult } from '@fracta/web-scan'
import { ReportView } from './ReportView'

type ScanResponse = { shareId?: string; result?: PassiveScanResult; error?: string }

export function ScanForm({ autoFocus = false }: { autoFocus?: boolean }) {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [inline, setInline] = useState<PassiveScanResult | null>(null)
  const errRef = useRef<HTMLParagraphElement>(null)
  const router = useRouter()

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    const value = url.trim()
    if (!value) return
    setLoading(true)
    setError(null)
    setInline(null)
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value }),
      })
      const data: ScanResponse = await res.json()
      if (!res.ok) {
        setError(data.error ?? 'Não foi possível analisar agora. Tente novamente.')
        setTimeout(() => errRef.current?.focus(), 0)
        return
      }
      if (data.shareId) {
        router.push(`/r/${data.shareId}`)
        return
      }
      if (data.result) setInline(data.result) // store indisponível — mostra inline
    } catch {
      setError('Falha de rede ao analisar. Verifique sua conexão e tente de novo.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="w-full">
      <form onSubmit={onSubmit} className="flex flex-col gap-2 sm:flex-row">
        <label htmlFor="scan-url" className="sr-only">URL para analisar</label>
        <input
          id="scan-url"
          type="text"
          inputMode="url"
          autoComplete="url"
          autoFocus={autoFocus}
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://seusaas.com.br"
          aria-busy={loading}
          aria-invalid={!!error}
          className="flex-1 rounded-md border border-border-strong bg-bg px-4 py-3 font-mono text-sm text-text placeholder:text-faint focus:border-accent focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="rounded-md border border-accent bg-accent/10 px-5 py-3 font-medium text-accent transition-colors hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? 'Analisando…' : 'Analisar grátis'}
        </button>
      </form>
      {error && (
        <p ref={errRef} tabIndex={-1} role="alert" className="mt-2 text-sm text-[var(--sev-high)]">
          {error}
        </p>
      )}
      <p className="mt-2 font-mono text-xs text-faint">
        Apenas GETs passivos. Não escaneamos endereços internos/privados.
      </p>
      {inline && (
        <div className="mt-8">
          <ReportView result={inline} />
        </div>
      )}
    </div>
  )
}
