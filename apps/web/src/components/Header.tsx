'use client'

import { useState } from 'react'
import { Wordmark } from '@/components/Wordmark'
import { REPO_URL } from '@/lib/config'

const NAV_LINKS = [
  { href: '#medimos', label: 'o que medimos' },
  { href: '/mcp', label: 'editor & CLI' },
  { href: '/blog', label: 'blog' },
] as const

export function Header() {
  const [open, setOpen] = useState(false)

  return (
    <header className="relative mx-auto max-w-content px-5 py-5">
      <div className="flex items-center justify-between gap-4">
        <Wordmark className="text-base" />

        {/* desktop nav */}
        <nav className="hidden items-center gap-5 text-sm text-muted md:flex">
          {NAV_LINKS.map((l) => (
            <a key={l.href} href={l.href} className="hover:text-text">
              {l.label}
            </a>
          ))}
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-xs hover:text-accent"
          >
            github ↗
          </a>
        </nav>

        {/* mobile toggle */}
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls="mobile-nav"
          aria-label={open ? 'Fechar menu' : 'Abrir menu'}
          className="-mr-1 inline-flex h-9 w-9 items-center justify-center rounded border border-border text-muted hover:border-border-strong hover:text-text md:hidden"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden>
            {open ? (
              <>
                <line x1="5" y1="5" x2="19" y2="19" />
                <line x1="19" y1="5" x2="5" y2="19" />
              </>
            ) : (
              <>
                <line x1="3" y1="7" x2="21" y2="7" />
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="17" x2="21" y2="17" />
              </>
            )}
          </svg>
        </button>
      </div>

      {/* mobile dropdown */}
      {open && (
        <nav
          id="mobile-nav"
          className="mt-4 flex flex-col border-t border-border pt-2 text-sm md:hidden"
        >
          {NAV_LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              onClick={() => setOpen(false)}
              className="py-2.5 text-muted hover:text-text"
            >
              {l.label}
            </a>
          ))}
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => setOpen(false)}
            className="py-2.5 font-mono text-xs text-muted hover:text-accent"
          >
            github ↗
          </a>
        </nav>
      )}
    </header>
  )
}
