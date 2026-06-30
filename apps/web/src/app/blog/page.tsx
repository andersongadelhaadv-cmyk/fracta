import type { Metadata } from 'next'
import Link from 'next/link'
import { Wordmark } from '@/components/Wordmark'
import { Footer } from '@/components/Footer'
import { getAllPosts } from '@/lib/blog'

const SITE = 'https://fracta.pro'

export const metadata: Metadata = {
  title: 'Blog — segurança web e LGPD para SaaS',
  description:
    'Guias diretos de segurança web e LGPD para quem constrói SaaS no Brasil: security headers, cookies, HSTS, política de privacidade e o que a ANPD realmente cobra. Sem encheção, com como testar de graça.',
  alternates: { canonical: `${SITE}/blog` },
  openGraph: {
    type: 'website',
    url: `${SITE}/blog`,
    title: 'Blog do Fracta — segurança web e LGPD para SaaS',
    description: 'Guias diretos de segurança web e LGPD para quem constrói SaaS no Brasil.',
    images: [{ url: '/brand/og.png', width: 1200, height: 630, alt: 'Blog do Fracta' }],
  },
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('pt-BR', { day: '2-digit', month: 'short', year: 'numeric' })
  } catch {
    return iso
  }
}

export default function BlogIndex() {
  const posts = getAllPosts()

  return (
    <main className="relative min-h-screen">
      <header className="mx-auto flex max-w-content items-center justify-between px-5 py-5">
        <Link href="/"><Wordmark className="text-base" /></Link>
        <nav className="flex items-center gap-5 text-sm text-muted">
          <Link href="/blog" className="text-text">blog</Link>
          <Link href="/" className="font-mono text-xs text-accent hover:underline">analisar um site →</Link>
        </nav>
      </header>

      {/* cabeçalho da seção */}
      <section className="relative overflow-hidden border-b border-border">
        <div className="grid-backdrop pointer-events-none absolute inset-0" aria-hidden />
        <div className="relative mx-auto max-w-content px-5 py-16">
          <p className="font-mono text-xs uppercase tracking-wide text-accent">blog · segurança &amp; LGPD</p>
          <h1 className="mt-4 max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight text-text sm:text-5xl">
            O que medir, o que arrumar e por quê.
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-muted">
            Segurança web e LGPD explicadas por quem constrói SaaS e responde por dados — sem teoria solta. Cada
            guia mostra <span className="text-text">como testar de graça</span> no seu próprio site.
          </p>
        </div>
      </section>

      {/* lista */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-12">
          {posts.length === 0 ? (
            <p className="font-mono text-sm text-muted">Em breve.</p>
          ) : (
            <ul className="grid gap-5 md:grid-cols-2">
              {posts.map((post) => (
                <li key={post.slug}>
                  <Link
                    href={`/blog/${post.slug}`}
                    className="group flex h-full flex-col rounded-md border border-border bg-surface p-6 transition-colors hover:border-accent/50"
                  >
                    <div className="flex items-center gap-3 font-mono text-[11px] uppercase tracking-wide text-faint">
                      <span>{fmtDate(post.date)}</span>
                      <span aria-hidden>·</span>
                      <span>{post.readingMinutes} min</span>
                    </div>
                    <h2 className="mt-3 text-xl font-semibold leading-snug text-text group-hover:text-accent">
                      {post.title}
                    </h2>
                    <p className="mt-2 flex-1 text-sm leading-relaxed text-muted">{post.description}</p>
                    {post.tags.length > 0 && (
                      <div className="mt-4 flex flex-wrap gap-2">
                        {post.tags.slice(0, 3).map((tag) => (
                          <span key={tag} className="rounded border border-border px-2 py-0.5 font-mono text-[10px] text-muted">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <Footer />
    </main>
  )
}
