import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { Wordmark } from '@/components/Wordmark'
import { Footer } from '@/components/Footer'
import { ScanForm } from '@/components/ScanForm'
import { getAllSlugs, getPostBySlug } from '@/lib/blog'

const SITE = 'https://fracta.pro'

export function generateStaticParams() {
  return getAllSlugs().map((slug) => ({ slug }))
}

export async function generateMetadata({ params }: { params: { slug: string } }): Promise<Metadata> {
  const post = await getPostBySlug(params.slug)
  if (!post) return { title: 'Artigo não encontrado' }
  const url = `${SITE}/blog/${post.slug}`
  return {
    title: post.title,
    description: post.description,
    keywords: post.tags,
    alternates: { canonical: url },
    openGraph: {
      type: 'article',
      url,
      title: post.title,
      description: post.description,
      publishedTime: post.date,
      modifiedTime: post.updated ?? post.date,
      authors: [post.author],
      images: [{ url: `${url}/opengraph-image`, width: 1200, height: 630, alt: post.title }],
    },
    twitter: {
      card: 'summary_large_image',
      title: post.title,
      description: post.description,
    },
  }
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' })
  } catch {
    return iso
  }
}

export default async function ArticlePage({ params }: { params: { slug: string } }) {
  const post = await getPostBySlug(params.slug)
  if (!post) notFound()

  const url = `${SITE}/blog/${post.slug}`
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: post.title,
    description: post.description,
    datePublished: post.date,
    dateModified: post.updated ?? post.date,
    author: { '@type': 'Person', name: post.author },
    publisher: {
      '@type': 'Organization',
      name: 'Fracta',
      logo: { '@type': 'ImageObject', url: `${SITE}/brand/og.png` },
    },
    mainEntityOfPage: { '@type': 'WebPage', '@id': url },
    keywords: post.tags.join(', '),
    inLanguage: 'pt-BR',
  }

  return (
    <main className="relative min-h-screen">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />

      <header className="mx-auto flex max-w-content items-center justify-between px-5 py-5">
        <Link href="/"><Wordmark className="text-base" /></Link>
        <nav className="flex items-center gap-5 text-sm text-muted">
          <Link href="/blog" className="hover:text-text">blog</Link>
          <Link href="/" className="font-mono text-xs text-accent hover:underline">analisar um site →</Link>
        </nav>
      </header>

      <article className="mx-auto max-w-2xl px-5 py-10">
        {/* breadcrumb */}
        <nav className="font-mono text-xs text-faint">
          <Link href="/blog" className="hover:text-accent">blog</Link>
          <span className="mx-2" aria-hidden>/</span>
          <span className="text-muted">{post.tags[0] ?? 'artigo'}</span>
        </nav>

        <h1 className="mt-5 text-3xl font-semibold leading-tight tracking-tight text-text sm:text-4xl">
          {post.title}
        </h1>

        <div className="mt-4 flex flex-wrap items-center gap-3 font-mono text-xs text-faint">
          <span>{post.author}</span>
          <span aria-hidden>·</span>
          <time dateTime={post.date}>{fmtDate(post.date)}</time>
          <span aria-hidden>·</span>
          <span>{post.readingMinutes} min de leitura</span>
        </div>

        <div className="prose mt-10" dangerouslySetInnerHTML={{ __html: post.html }} />

        {/* CTA — converte leitura em scan */}
        <aside className="mt-14 rounded-md border border-accent/30 bg-surface p-6">
          <p className="font-mono text-xs uppercase tracking-wide text-accent">teste agora · grátis</p>
          <p className="mt-3 text-base text-text">
            Veja a nota A–F do <span className="text-text">seu</span> site em segundos.
          </p>
          <p className="mt-1 text-sm text-muted">
            Headers, TLS, cookies e sinais de LGPD — detecção determinística, sem cadastro.
          </p>
          <div className="mt-5">
            <ScanForm />
          </div>
        </aside>
      </article>

      <Footer />
    </main>
  )
}
