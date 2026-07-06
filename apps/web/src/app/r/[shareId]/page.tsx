import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { getStore } from '@/lib/scan-store'
import { ReportView } from '@/components/ReportView'
import { EditorCta } from '@/components/EditorCta'
import { Wordmark } from '@/components/Wordmark'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

function getResult(shareId: string) {
  const store = getStore()
  return store?.getByShareId(shareId) ?? null
}

export function generateMetadata({ params }: { params: { shareId: string } }): Metadata {
  const result = getResult(params.shareId)
  if (!result) return { title: 'Relatório não encontrado' }
  let host = result.url
  try { host = new URL(result.url).host } catch { /* mantém */ }
  const grade = result.grade ? `Nota ${result.grade}` : 'Inconclusivo'
  const title = `${grade} · ${host}`
  return {
    title,
    description: `Relatório passivo de segurança e LGPD de ${host} pelo Fracta.`,
    openGraph: {
      title: `${title} · Fracta`,
      description: `Headers, TLS, cookies e LGPD-lite de ${host}.`,
      // imagem OG = card dinâmico 1200×630 (opengraph-image.tsx, convenção do Next).
    },
  }
}

export default function ResultPage({ params }: { params: { shareId: string } }) {
  const result = getResult(params.shareId)
  if (!result) notFound()

  // Medição agregada (1x por render de página; generateMetadata não conta):
  // um relatório compartilhado foi aberto — sinal de alcance viral. Sem PII.
  getStore()?.bump('report_view')

  return (
    <main className="min-h-screen">
      <header className="mx-auto flex max-w-content items-center justify-between px-5 py-5">
        <Link href="/"><Wordmark className="text-base" /></Link>
        <Link href="/" className="font-mono text-xs text-accent hover:underline">nova análise →</Link>
      </header>
      <div className="px-5 pb-8">
        <ReportView result={result} shareId={params.shareId} />
      </div>
      <div className="pb-16">
        <EditorCta />
      </div>
    </main>
  )
}
