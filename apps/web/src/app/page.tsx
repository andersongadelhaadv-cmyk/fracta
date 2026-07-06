import { Wordmark } from '@/components/Wordmark'
import { ScanForm } from '@/components/ScanForm'
import { SampleReport } from '@/components/SampleReport'
import { Pipeline } from '@/components/Pipeline'
import { FleetProof } from '@/components/FleetProof'
import { ZapApiSupporter } from '@/components/ZapApiSupporter'
import { Footer } from '@/components/Footer'
import { CopyBlock } from '@/components/CopyBlock'
import { REPO_URL, MCP_INSTALL_CMD } from '@/lib/config'

export default function Home() {
  return (
    <main className="relative">
      {/* nav */}
      <header className="mx-auto flex max-w-content items-center justify-between px-5 py-5">
        <Wordmark className="text-base" />
        <nav className="flex items-center gap-5 text-sm text-muted">
          <a href="#medimos" className="hover:text-text">o que medimos</a>
          <a href="/mcp" className="hover:text-text">editor &amp; CLI</a>
          <a href="/blog" className="hover:text-text">blog</a>
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="font-mono text-xs hover:text-accent">
            github ↗
          </a>
        </nav>
      </header>

      {/* hero */}
      <section className="relative overflow-hidden border-b border-border">
        <div className="grid-backdrop pointer-events-none absolute inset-0" aria-hidden />
        <div className="relative mx-auto grid max-w-content items-center gap-12 px-5 py-16 lg:grid-cols-2 lg:py-24">
          <div>
            <p className="font-mono text-xs uppercase tracking-wide text-accent">scanner passivo · headers · TLS · cookies · LGPD</p>
            <h1 className="mt-4 text-4xl font-semibold leading-[1.1] tracking-tight text-text sm:text-5xl">
              O que o seu SaaS entrega<br />antes mesmo do login.
            </h1>
            <p className="mt-5 max-w-xl text-lg leading-relaxed text-muted">
              O Fracta lê os headers de segurança, o TLS, as flags de cookie e sinais de LGPD do seu site — só com
              requisições passivas. Nota A–F na hora, detecção determinística (sem palpite de IA), e dizemos quando
              <span className="text-text"> não</span> conseguimos verificar.
            </p>
            <div className="mt-8 max-w-xl">
              <ScanForm autoFocus />
            </div>
            <p className="mt-5 text-sm text-muted">
              <span className="font-mono font-medium text-accent">100% grátis</span>{' '}
              <span className="text-faint font-mono text-xs">· sem cadastro · resultado na hora · open-source · 12 SaaS da nossa frota auditados</span>
            </p>
          </div>
          <div className="relative">
            <div className="scanline" aria-hidden />
            <SampleReport />
          </div>
        </div>
      </section>

      {/* como funciona */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-12">
          <h2 className="font-mono text-xs uppercase tracking-wide text-muted">como funciona</h2>
          <div className="mt-4">
            <Pipeline />
          </div>
          <p className="mt-4 max-w-2xl text-sm text-muted">
            Toda URL passa por um <span className="text-text">SSRF guard</span> que valida o IP real no momento da
            conexão (bloqueia interno/privado/metadata, inclusive via redirect). Só então rodam os checks passivos.
          </p>
        </div>
      </section>

      {/* além do scanner web: MCP + CLI */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-12">
          <p className="font-mono text-xs uppercase tracking-wide text-accent">editor · terminal · CI</p>
          <h2 className="mt-3 max-w-3xl text-2xl font-semibold tracking-tight text-text sm:text-3xl">
            O scanner web é só a porta. Use o Fracta no seu editor e no seu CI.
          </h2>
          <p className="mt-4 max-w-2xl text-sm leading-relaxed text-muted">
            O mesmo motor determinístico, dentro do <span className="text-text">Claude</span> (via MCP) e no seu terminal
            (via CLI). Roda na sua máquina — sem login, sem conta.
          </p>
          <div className="mt-6 max-w-2xl">
            <CopyBlock text={MCP_INSTALL_CMD} />
          </div>
          <div className="mt-8 grid gap-5 sm:grid-cols-3">
            <div>
              <p className="font-mono text-sm text-accent">MCP no editor</p>
              <p className="mt-2 text-sm text-muted">O Claude audita o repositório que você está codando — deps, secrets, código, LGPD. Read-only.</p>
            </div>
            <div>
              <p className="font-mono text-sm text-accent">CLI no CI</p>
              <p className="mt-2 text-sm text-muted">Roda no pipeline e falha o build se achar algo crítico. Zero install global (npx).</p>
            </div>
            <div>
              <p className="font-mono text-sm text-accent">verify (LGPD)</p>
              <p className="mt-2 text-sm text-muted">Um browser real confirma trackers/cookies que disparam antes do consentimento — prova, não palpite.</p>
            </div>
          </div>
          <a href="/mcp" className="mt-8 inline-block font-mono text-sm text-accent hover:underline">ver todas as ferramentas →</a>
        </div>
      </section>

      {/* o que medimos / não medimos */}
      <section id="medimos" className="border-b border-border">
        <div className="mx-auto grid max-w-content gap-6 px-5 py-12 md:grid-cols-2">
          <div className="rounded-md border border-border bg-surface p-6">
            <h3 className="font-mono text-xs uppercase tracking-wide text-[var(--grade-a)]">medimos</h3>
            <ul className="mt-4 space-y-3 text-sm text-muted">
              <li><span className="text-text">Security headers</span> — HSTS, X-Content-Type-Options, X-Frame-Options, Referrer/Permissions-Policy, CORS.</li>
              <li><span className="text-text">TLS / HTTPS</span> — o alvo força HTTPS e responde com TLS válido.</li>
              <li><span className="text-text">Flags de cookie</span> — Secure, HttpOnly, SameSite nos <code className="font-mono text-xs">Set-Cookie</code>.</li>
              <li><span className="text-text">LGPD-lite (beta)</span> — <span className="text-text">lemos a sua Política de Privacidade</span> e conferimos os itens do Art. 9º (encarregado, base legal, direitos do titular, retenção, transferência internacional), além de rastreadores de terceiros e cookies não-essenciais. Determinístico, sem IA.</li>
            </ul>
          </div>
          <div className="rounded-md border border-border bg-surface p-6">
            <h3 className="font-mono text-xs uppercase tracking-wide text-[var(--sev-high)]">não medimos</h3>
            <ul className="mt-4 space-y-3 text-sm text-muted">
              <li><span className="text-text">Nada de ataque ativo</span> — sem IDOR, SQLi, brute-force. Rodar isso contra uma URL de terceiro é invadir, não auditar.</li>
              <li><span className="text-text">Sem login</span> — só a superfície pública. O que está atrás de auth é CLI, com prova de propriedade.</li>
              <li><span className="text-text">Sem “100% seguro”</span> — passivo vê uma fatia. Um A aqui é um bom sinal, não um certificado.</li>
              <li><span className="text-text">Ausência de achado ≠ seguro</span> — se um check não roda, ele aparece como <span className="text-faint">não verificado</span>.</li>
            </ul>
          </div>
        </div>
      </section>

      {/* por que confiar */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-12">
          <h2 className="font-mono text-xs uppercase tracking-wide text-muted">por que confiar</h2>
          <div className="mt-6 grid gap-6 md:grid-cols-3">
            <div>
              <p className="font-mono text-sm text-accent">determinístico</p>
              <p className="mt-2 text-sm text-muted">A mesma engine do CLI open-source. Regras, não alucinação de IA — o mesmo achado dá sempre o mesmo resultado.</p>
            </div>
            <div>
              <p className="font-mono text-sm text-accent">segurança × LGPD</p>
              <p className="mt-2 text-sm text-muted">Construído por um advogado que opera uma frota de legaltech. Segurança técnica cruzada com LGPD de verdade.</p>
            </div>
            <div>
              <p className="font-mono text-sm text-accent">honesto por design</p>
              <p className="mt-2 text-sm text-muted">Um check que não roda nunca vira verde. Alvo fora do ar fica inconclusivo — sem nota, sem fingimento.</p>
            </div>
          </div>
        </div>
      </section>

      {/* prova: notas reais da frota */}
      <FleetProof />

      {/* auto-auditoria LGPD — praticamos o que pregamos */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-12">
          <div className="rounded-md border border-border bg-surface p-6">
            <p className="font-mono text-xs uppercase tracking-wide text-accent">praticamos o que pregamos</p>
            <p className="mt-3 max-w-3xl text-sm leading-relaxed text-muted">
              Não auditamos só a superfície dos outros. Rodamos a auditoria <span className="text-text">completa de LGPD</span> —
              as <span className="text-text">16 dimensões</span> da lei (bases legais, transferência internacional, retenção,
              encarregado, governança) — <span className="text-text">em nós mesmos</span>. Resultado: <span className="text-text">adequado em 100%</span>,
              com ROPA, plano de incidentes e TIA arquivados.{' '}
              <a href="/privacidade" className="text-accent hover:underline">Nossa Política de Privacidade →</a>
            </p>
          </div>
        </div>
      </section>

      {/* ecossistema */}
      <section className="border-b border-border">
        <div className="mx-auto max-w-content px-5 py-10">
          <ZapApiSupporter />
        </div>
      </section>

      {/* footer */}
      <Footer />
    </main>
  )
}
