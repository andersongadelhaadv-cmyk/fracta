import Link from 'next/link'
import { Wordmark } from './Wordmark'
import { REPO_URL, ZAP_API_URL, PREVIUSIA_URL } from '@/lib/config'

const ext = { target: '_blank', rel: 'noopener noreferrer' } as const

export function Footer() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto max-w-content px-5 py-14">
        <div className="grid gap-10 md:grid-cols-[1.4fr_1fr_1fr_1fr]">
          {/* marca + autoria */}
          <div>
            <Wordmark className="text-base" />
            <p className="mt-3 max-w-xs text-sm leading-relaxed text-muted">
              Scanner de segurança e LGPD para SaaS. Detecção determinística, open-source, dirigida a prova.
            </p>
            <a {...ext} href={PREVIUSIA_URL} className="mt-4 inline-block font-mono text-xs text-muted hover:text-accent">
              desenvolvido por <span className="text-text">PreviusIA</span> ↗
            </a>
          </div>

          {/* produto */}
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wide text-faint">produto</p>
            <ul className="mt-3 space-y-2 text-sm text-muted">
              <li><Link href="/" className="hover:text-text">Analisar um site</Link></li>
              <li><Link href="/#medimos" className="hover:text-text">O que medimos</Link></li>
              <li><Link href="/#medimos" className="hover:text-text">Como funciona</Link></li>
            </ul>
          </div>

          {/* open source */}
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wide text-faint">open source</p>
            <ul className="mt-3 space-y-2 text-sm text-muted">
              <li><a {...ext} href={REPO_URL} className="hover:text-text">Repositório ↗</a></li>
              <li><a {...ext} href={`${REPO_URL}#readme`} className="hover:text-text">CLI &amp; docs ↗</a></li>
              <li><a {...ext} href={`${REPO_URL}/issues`} className="hover:text-text">Issues ↗</a></li>
            </ul>
          </div>

          {/* ecossistema */}
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wide text-faint">ecossistema</p>
            <ul className="mt-3 space-y-2 text-sm text-muted">
              <li><a {...ext} href={ZAP_API_URL} className="hover:text-text">ZAP-API ↗</a></li>
              <li><a {...ext} href={PREVIUSIA_URL} className="hover:text-text">PreviusIA ↗</a></li>
            </ul>
          </div>
        </div>

        {/* barra inferior */}
        <div className="mt-12 flex flex-col items-start justify-between gap-3 border-t border-border pt-6 sm:flex-row sm:items-center">
          <p className="font-mono text-xs text-faint">© 2026 PreviusIA · detecção determinística · sem cadastro</p>
          <div className="flex flex-wrap items-center gap-5 font-mono text-xs">
            <Link href="/privacidade" className="text-muted hover:text-accent">Política de Privacidade</Link>
            <span className="text-faint">feito no Brasil</span>
          </div>
        </div>
      </div>
    </footer>
  )
}
