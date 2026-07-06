import type { Metadata } from 'next'
import Link from 'next/link'
import { Wordmark } from '@/components/Wordmark'
import { Footer } from '@/components/Footer'
import { CopyBlock } from '@/components/CopyBlock'
import { MCP_INSTALL_CMD, MCP_JSON_CONFIG, MCP_TOOLS, REPO_URL } from '@/lib/config'

const ext = { target: '_blank', rel: 'noopener noreferrer' } as const

export const metadata: Metadata = {
  title: 'Use no seu editor e terminal — MCP & CLI',
  description:
    'Instale o Fracta no Claude e na linha de comando: audite seu repositório e seus SaaS direto do editor. Roda na sua máquina, sem login e sem conta. 10 ferramentas MCP.',
  alternates: { canonical: '/mcp' },
  openGraph: { title: 'Fracta no seu editor (MCP) e terminal (CLI)', url: 'https://fracta.pro/mcp' },
}

const zeroTools = MCP_TOOLS.filter((t) => t.group === 'zero')
const targetTools = MCP_TOOLS.filter((t) => t.group === 'targets')

function SafetyBadge({ intrusive }: { intrusive: boolean }) {
  return intrusive ? (
    <span className="rounded border border-[var(--sev-high)]/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-[var(--sev-high)]">
      intrusivo · só sites seus
    </span>
  ) : (
    <span className="rounded border border-[var(--grade-a)]/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-[var(--grade-a)]">
      passivo · seguro
    </span>
  )
}

function ToolCard({ name, desc, intrusive }: { name: string; desc: string; intrusive: boolean }) {
  return (
    <div className="rounded-md border border-border bg-surface p-5">
      <div className="flex items-center justify-between gap-3">
        <code className="font-mono text-sm text-accent">{name}</code>
        <SafetyBadge intrusive={intrusive} />
      </div>
      <p className="mt-3 text-sm leading-relaxed text-muted">{desc}</p>
    </div>
  )
}

export default function McpPage() {
  return (
    <main className="relative">
      {/* header */}
      <header className="mx-auto flex max-w-content items-center justify-between px-5 py-5">
        <Link href="/"><Wordmark className="text-base" /></Link>
        <nav className="flex items-center gap-5 text-sm text-muted">
          <Link href="/#medimos" className="hover:text-text">o que medimos</Link>
          <Link href="/blog" className="hover:text-text">blog</Link>
          <Link href="/" className="font-mono text-xs text-accent hover:underline">analisar um site →</Link>
        </nav>
      </header>

      {/* hero */}
      <section className="relative overflow-hidden border-b border-border">
        <div className="grid-backdrop pointer-events-none absolute inset-0" aria-hidden />
        <div className="relative mx-auto max-w-content px-5 py-16 lg:py-20">
          <p className="font-mono text-xs uppercase tracking-wide text-accent">editor · terminal · CI</p>
          <h1 className="mt-4 max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight text-text sm:text-5xl">
            O scanner é só a porta. Leve o Fracta pro seu editor.
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-muted">
            O mesmo motor determinístico do site, agora dentro do <span className="text-text">Claude</span> (via MCP) e no seu
            <span className="text-text"> terminal</span> (via CLI). Instala num comando, <span className="text-text">roda na sua
            máquina</span> — sem login, sem conta, sem enviar seu código pra lugar nenhum. O controle de acesso é o seu próprio ambiente.
          </p>
        </div>
      </section>

      {/* quickstart 3 passos */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-14">
          <h2 className="font-mono text-xs uppercase tracking-wide text-muted">comece em 3 passos</h2>

          {/* passo 1 */}
          <div className="mt-8 grid gap-4 md:grid-cols-[auto_1fr] md:gap-6">
            <div className="font-mono text-2xl text-accent-dim">1</div>
            <div>
              <p className="text-text">Instale no Claude Code (um comando):</p>
              <div className="mt-3 max-w-2xl">
                <CopyBlock text={MCP_INSTALL_CMD} />
              </div>
              <details className="mt-3 max-w-2xl">
                <summary className="cursor-pointer font-mono text-xs text-muted hover:text-accent">
                  outro cliente (Claude Desktop, Cursor…)? use este JSON de config
                </summary>
                <div className="mt-3">
                  <CopyBlock text={MCP_JSON_CONFIG} multiline />
                </div>
              </details>
            </div>
          </div>

          {/* passo 2 */}
          <div className="mt-10 grid gap-4 md:grid-cols-[auto_1fr] md:gap-6">
            <div className="font-mono text-2xl text-accent-dim">2</div>
            <div>
              <p className="text-text">Peça em português. Exemplos:</p>
              <ul className="mt-3 space-y-2 font-mono text-sm text-muted">
                <li className="rounded border border-border bg-surface px-3 py-2">“escaneie o repositório deste projeto”</li>
                <li className="rounded border border-border bg-surface px-3 py-2">“analise os headers de https://meusaas.com.br”</li>
                <li className="rounded border border-border bg-surface px-3 py-2">“verifique se o site dispara trackers antes do consentimento”</li>
              </ul>
              <p className="mt-3 text-sm text-muted">O Claude escolhe a ferramenta certa e traz a nota + os achados. Nenhuma config pra isso.</p>
            </div>
          </div>

          {/* passo 3 */}
          <div className="mt-10 grid gap-4 md:grid-cols-[auto_1fr] md:gap-6">
            <div className="font-mono text-2xl text-accent-dim">3</div>
            <div>
              <p className="text-text">
                <span className="text-muted">(opcional)</span> Para os testes que tocam áreas autenticadas dos <span className="text-text">seus</span> sistemas,
                declare os alvos num <code className="font-mono text-xs text-accent">targets.yaml</code>.
              </p>
              <p className="mt-3 text-sm text-muted">
                É isso que autoriza os testes intrusivos: eles só rodam contra o que <span className="text-text">você</span> declarou.
                Sem esse arquivo, as 4 ferramentas passivas abaixo já funcionam.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* tools zero-config em destaque */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-14">
          <h2 className="text-2xl font-semibold tracking-tight text-text">Sem configurar nada</h2>
          <p className="mt-2 max-w-2xl text-sm text-muted">
            Funcionam no primeiro minuto, direto do editor — em qualquer site ou no repositório que você está codando.
          </p>
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            {zeroTools.map((t) => (
              <ToolCard key={t.name} name={t.name} desc={t.desc} intrusive={t.intrusive} />
            ))}
          </div>
        </div>
      </section>

      {/* guarda-corpo passivo × intrusivo */}
      <section className="border-b border-border">
        <div className="mx-auto grid max-w-content gap-6 px-5 py-14 md:grid-cols-2">
          <div className="rounded-md border border-[var(--grade-a)]/30 bg-surface p-6">
            <p className="font-mono text-xs uppercase tracking-wide text-[var(--grade-a)]">passivo · seguro em qualquer site</p>
            <p className="mt-3 text-sm leading-relaxed text-muted">
              Só faz requisições de leitura (GET). Não invade, não testa senha, não muda nada. Pode rodar contra qualquer URL sem risco — é o que o scanner do site faz.
            </p>
          </div>
          <div className="rounded-md border border-[var(--sev-high)]/30 bg-surface p-6">
            <p className="font-mono text-xs uppercase tracking-wide text-[var(--sev-high)]">intrusivo · só nos seus sistemas</p>
            <p className="mt-3 text-sm leading-relaxed text-muted">
              Testa autenticação e acesso cruzado — comportamento de atacante. Rodar contra site de terceiro é invadir. Por isso exige o <code className="font-mono text-xs text-text">targets.yaml</code> com alvos que você controla.
            </p>
          </div>
        </div>
      </section>

      {/* tabela completa */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-14">
          <h2 className="font-mono text-xs uppercase tracking-wide text-muted">as 10 ferramentas</h2>

          <h3 className="mt-6 text-sm text-text">Sem config <span className="text-faint">— funcionam já</span></h3>
          <div className="mt-3 grid gap-3">
            {zeroTools.map((t) => (
              <div key={t.name} className="grid gap-1 rounded-md border border-border bg-surface p-4 sm:grid-cols-[220px_1fr] sm:items-baseline sm:gap-4">
                <code className="font-mono text-sm text-accent">{t.name}</code>
                <p className="text-sm text-muted">{t.desc}</p>
              </div>
            ))}
          </div>

          <h3 className="mt-8 text-sm text-text">Precisam do <code className="font-mono text-xs text-accent">targets.yaml</code> <span className="text-faint">— alvos que você declara</span></h3>
          <div className="mt-3 grid gap-3">
            {targetTools.map((t) => (
              <div key={t.name} className="grid gap-1 rounded-md border border-border bg-surface p-4 sm:grid-cols-[220px_1fr] sm:items-baseline sm:gap-4">
                <div className="flex items-center gap-2">
                  <code className="font-mono text-sm text-accent">{t.name}</code>
                  {t.intrusive && <span className="font-mono text-[10px] uppercase text-[var(--sev-high)]">intrusivo</span>}
                </div>
                <p className="text-sm text-muted">{t.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CLI */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-14">
          <h2 className="text-2xl font-semibold tracking-tight text-text">Prefere o terminal? Use o CLI</h2>
          <p className="mt-2 max-w-2xl text-sm text-muted">
            Mesmo motor, sem instalar nada global — o <code className="font-mono text-xs text-text">npx</code> resolve. Ideal pra rodar no CI (falha o build se achar algo crítico).
          </p>
          <div className="mt-6 max-w-2xl space-y-3">
            <CopyBlock text="npx fractascan verify https://meusaas.com.br" />
            <CopyBlock text="npx fractascan scan --target meu-saas --fail-on critical,high" />
            <CopyBlock text="npx fractascan docs --docs-path ./" />
          </div>
          <p className="mt-4 text-sm text-muted">
            <code className="font-mono text-xs text-accent">verify</code> abre um browser (usa o Chrome do sistema ou <code className="font-mono text-xs text-text">npx playwright install chromium</code>).
            {' '}<code className="font-mono text-xs text-accent">scan</code> lê o <code className="font-mono text-xs text-text">targets.yaml</code>.{' '}
            <a {...ext} href={`${REPO_URL}#readme`} className="text-accent hover:underline">docs completas no GitHub ↗</a>
          </p>
        </div>
      </section>

      <Footer />
    </main>
  )
}
