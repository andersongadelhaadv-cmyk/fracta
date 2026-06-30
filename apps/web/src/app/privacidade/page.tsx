import type { Metadata } from 'next'
import Link from 'next/link'
import { Wordmark } from '@/components/Wordmark'
import { Footer } from '@/components/Footer'

export const metadata: Metadata = {
  title: 'Política de Privacidade',
  description: 'Como o Fracta trata dados pessoais — em conformidade com a LGPD (Lei 13.709/2018).',
}

const PRIVACY_EMAIL = 'privacidade@previusia.com.br'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-8">
      <h2 className="font-mono text-xs uppercase tracking-wide text-accent">{title}</h2>
      <div className="mt-3 space-y-3 text-sm leading-relaxed text-muted">{children}</div>
    </section>
  )
}

export default function Privacidade() {
  return (
    <main className="min-h-screen">
      <header className="mx-auto flex max-w-content items-center justify-between px-5 py-5">
        <Link href="/"><Wordmark className="text-base" /></Link>
        <Link href="/" className="font-mono text-xs text-accent hover:underline">← voltar</Link>
      </header>

      <article className="mx-auto max-w-3xl px-5 py-10">
        <h1 className="text-3xl font-semibold tracking-tight text-text">Política de Privacidade</h1>
        <p className="mt-3 text-sm text-faint">
          Em conformidade com a LGPD (Lei 13.709/2018). Última atualização: junho de 2026.
        </p>
        <p className="mt-6 text-sm leading-relaxed text-muted">
          O Fracta é operado pela <span className="text-text">PreviusIA</span>. Aqui explicamos, de forma direta e honesta,
          quais dados tratamos e por quê. Resumo: pouquíssimos — não há login, não há cookies de rastreamento, não vendemos nada.
        </p>

        <Section title="O que coletamos">
          <ul className="list-disc space-y-2 pl-5">
            <li><span className="text-text">URL que você analisa</span> e o <span className="text-text">resultado do scan</span> — armazenados para gerar o link compartilhável do relatório.</li>
            <li><span className="text-text">E-mail</span> — apenas se você optar pela lista de espera de monitoramento contínuo. É opcional.</li>
            <li><span className="text-text">Endereço IP</span> — usado em memória só para limitar abuso (rate-limit). Não é associado ao seu scan nem persistido junto com ele.</li>
          </ul>
          <p>Não usamos cookies de rastreamento, pixels ou analytics de terceiros. Não há cadastro nem perfilamento.</p>
        </Section>

        <Section title="Para que usamos">
          <p>Prestar o serviço de análise, gerar o relatório compartilhável, evitar abuso da ferramenta e — se você consentir — avisá-lo quando o monitoramento contínuo for lançado. Nada além disso.</p>
        </Section>

        <Section title="Base legal">
          <p>Legítimo interesse (LGPD art. 7º, IX) para executar a análise solicitada por você e proteger a ferramenta contra abuso; e consentimento (art. 7º, I) para o envio de e-mail à lista de espera, que você pode revogar a qualquer momento.</p>
        </Section>

        <Section title="O que NÃO fazemos">
          <p>O scanner faz apenas requisições GET passivas à superfície pública do endereço que você informa — não coletamos dados de usuários do site analisado, não fazemos login, não executamos ataques. Não vendemos, alugamos nem compartilhamos dados pessoais com terceiros para marketing.</p>
        </Section>

        <Section title="Retenção">
          <p>Relatórios de scan são mantidos por aproximadamente 90 dias e depois removidos automaticamente. E-mails da lista de espera ficam até você pedir a remoção.</p>
        </Section>

        <Section title="Seus direitos (LGPD art. 18)">
          <p>Você pode solicitar confirmação e acesso, correção, anonimização ou eliminação dos seus dados, portabilidade, e revogação do consentimento. Para exercer, escreva para <a href={`mailto:${PRIVACY_EMAIL}`} className="text-accent hover:underline">{PRIVACY_EMAIL}</a>.</p>
        </Section>

        <Section title="Encarregado (DPO) e contato">
          <p>Dúvidas ou solicitações sobre privacidade: <a href={`mailto:${PRIVACY_EMAIL}`} className="text-accent hover:underline">{PRIVACY_EMAIL}</a>.</p>
        </Section>
      </article>

      <Footer />
    </main>
  )
}
