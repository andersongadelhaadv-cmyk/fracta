import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { getStore } from '@/lib/scan-store'
import { ReportView } from '@/components/ReportView'
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
      images: [`/api/badge/${params.shareId}`],
    },
  }
}

export default function ResultPage({ params }: { params: { shareId: string } }) {
  const result = getResult(params.shareId)
  if (!result) notFound()

  return (
    <main className="min-h-screen">
      <header className="mx-auto flex max-w-content items-center justify-between px-5 py-5">
        <Link href="/"><Wordmark className="text-base" /></Link>
        <Link href="/" className="font-mono text-xs text-accent hover:underline">nova análise →</Link>
      </header>
      <div className="px-5 pb-16">
        <ReportView result={result} shareId={params.shareId} />
      </div>
    </main>
  )
}
