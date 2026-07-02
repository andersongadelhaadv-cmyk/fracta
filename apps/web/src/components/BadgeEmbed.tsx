'use client'

import { useState } from 'react'
import type { ScanGrade } from '@fracta/web-scan'

const SITE = 'https://fracta.pro'

/**
 * Loop de distribuição (#39): dá ao dono do site um badge "nota A · Fracta" com
 * LINK DE VOLTA p/ o relatório em fracta.pro. Cada badge embutido = um backlink
 * (SEO) e prova social (viral). Preview + snippet copiável — zero fricção.
 */
export function BadgeEmbed({ shareId, grade }: { shareId: string; grade: ScanGrade }) {
  const [copied, setCopied] = useState(false)
  const src = `${SITE}/api/badge/${shareId}`
  const href = `${SITE}/r/${shareId}`
  const snippet =
    `<a href="${href}" target="_blank" rel="noopener">\n` +
    `  <img src="${src}" alt="Segurança e LGPD analisadas por Fracta — nota ${grade}" width="150" height="40" />\n` +
    `</a>`

  async function copy() {
    try {
      await navigator.clipboard.writeText(snippet)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      /* clipboard indisponível — o usuário ainda pode selecionar o texto abaixo */
    }
  }

  return (
    <div className="rounded-md border border-border bg-surface p-6">
      <h2 className="font-mono text-xs uppercase tracking-wide text-muted">exiba seu badge</h2>
      <p className="mt-1 text-sm text-muted">
        Mostre a nota no seu site ou README. O badge sempre reflete o último resultado
        e leva de volta ao relatório completo.
      </p>
      <div className="mt-4 flex flex-col gap-4 sm:flex-row sm:items-center">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={src} alt={`Fracta — nota ${grade}`} width={150} height={40} className="shrink-0" />
        <div className="min-w-0 flex-1">
          <pre className="overflow-x-auto rounded border border-border bg-bg p-3 font-mono text-xs text-muted">
            <code>{snippet}</code>
          </pre>
        </div>
      </div>
      <button
        type="button"
        onClick={copy}
        className="mt-3 rounded border border-border px-3 py-1.5 font-mono text-xs text-accent transition-colors hover:border-accent"
      >
        {copied ? 'copiado ✓' : 'copiar HTML'}
      </button>
    </div>
  )
}
