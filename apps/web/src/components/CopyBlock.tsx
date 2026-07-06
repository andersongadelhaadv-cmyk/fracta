'use client'

import { useState } from 'react'

/**
 * Bloco de código com botão "copiar" (1 clique). Único componente client desta
 * feature — o Next aplica o nonce do CSP nele automaticamente.
 */
export function CopyBlock({ text, multiline = false }: { text: string; multiline?: boolean }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      // Clipboard indisponível (ex.: contexto não-seguro) — silencioso; o texto está visível p/ copiar à mão.
    }
  }

  return (
    <div className="group relative flex items-start gap-3 rounded-md border border-border bg-surface p-4">
      <pre
        className={`min-w-0 flex-1 overflow-x-auto font-mono text-sm text-text ${multiline ? 'leading-relaxed' : 'whitespace-pre'}`}
      >
        {text}
      </pre>
      <button
        type="button"
        onClick={copy}
        aria-label="Copiar"
        className="shrink-0 rounded border border-border px-2.5 py-1 font-mono text-xs text-muted transition-colors hover:border-accent hover:text-accent"
      >
        {copied ? '✓ copiado' : 'copiar'}
      </button>
    </div>
  )
}
