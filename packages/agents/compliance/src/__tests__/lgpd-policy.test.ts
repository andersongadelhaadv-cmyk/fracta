import { describe, it, expect } from 'vitest'
import { stripMarkup, findPolicyDoc, diffPolicyVsCode } from '../lgpd-policy.js'
import type { OperatorMatch } from '../lgpd-inventory.js'

const op = (name: string, international: boolean): OperatorMatch => ({
  name,
  purpose: 'x',
  international,
})

// Política "conforme" no estilo Veredicto: declara transferência internacional (Art. 33),
// lista Stripe/Resend/Sentry como operadores — mas NÃO menciona OpenAI (a IA declarada é Google).
const COMPLIANT_POLICY = `
export default function Privacidade() {
  return (
    <main>
      <h1 className="title">Política de Privacidade</h1>
      <section>
        <h2>6. Operadores e sub-processadores</h2>
        <table><tbody>
          <tr><td>Google (Gemini, login)</td><td>Inteligência artificial e autenticação</td></tr>
          <tr><td>Stripe</td><td>Processamento de pagamento por cartão</td></tr>
          <tr><td>Resend</td><td>Envio de e-mails transacionais</td></tr>
          <tr><td>Sentry</td><td>Monitoramento de erros e estabilidade</td></tr>
        </tbody></table>
      </section>
      <section>
        <h2>7. Transferência internacional de dados</h2>
        <p>
          Alguns operadores processam dados fora do Brasil. Nesses casos há
          transferência internacional de dados, com base no Art. 33 da LGPD.
        </p>
      </section>
      <section>
        <h2>8. Cookies e retenção</h2>
        <p>O titular pode revogar o consentimento. Base legal e retenção descritas.</p>
      </section>
    </main>
  )
}
`

// Política "muda" sobre internacional: fala de operadores, mas nenhuma palavra sobre
// transferência internacional / dados fora do Brasil (Art. 33 não declarado).
const SILENT_ON_INTL_POLICY = `
# Política de Privacidade

## Operadores
Utilizamos ferramentas de terceiros sob contrato para operar o serviço.

## Titular e base legal
O titular pode exercer seus direitos. Tratamos com base no legítimo interesse.
Cookies são usados. A retenção segue os prazos legais. Encarregado disponível.
`

describe('stripMarkup', () => {
  it('remove tags JSX/HTML e atributos, preservando o texto visível', () => {
    const out = stripMarkup('<td className="py-2 pr-4">Stripe</td>')
    expect(out).toBe('Stripe')
  })
  it('colapsa espaços e remove expressões {…}', () => {
    const out = stripMarkup('<p>Olá {name} mundo</p>')
    expect(out).toBe('Olá mundo')
  })
})

describe('findPolicyDoc', () => {
  it('acha a página de política publicada pelo path + conteúdo', () => {
    const files = [
      { relPath: 'apps/web/src/app/privacidade/page.tsx', content: COMPLIANT_POLICY },
      { relPath: 'apps/web/src/app/cadastro/page.tsx', content: '<a href="/privacidade">Política de Privacidade</a>' },
      { relPath: 'src/index.ts', content: 'export const x = 1' },
    ]
    const doc = findPolicyDoc(files)
    expect(doc).not.toBeNull()
    expect(doc!.relPath).toBe('apps/web/src/app/privacidade/page.tsx')
  })

  it('NÃO confunde um mero LINK para a política com o documento', () => {
    const files = [
      { relPath: 'src/components/Footer.tsx', content: '<a href="/privacidade">Política de Privacidade</a>' },
    ]
    expect(findPolicyDoc(files)).toBeNull()
  })

  it('retorna null quando não há política no repositório', () => {
    const files = [{ relPath: 'src/index.ts', content: 'export const x = 1' }]
    expect(findPolicyDoc(files)).toBeNull()
  })
})

describe('diffPolicyVsCode', () => {
  const operators = [op('Stripe', true), op('OpenAI', true), op('Resend', true), op('Sentry', true), op('Banco de dados (self-hosted)', false)]

  it('política conforme: internacional declarada, mas OpenAI (código) ausente → divergência real', () => {
    const doc = findPolicyDoc([{ relPath: 'privacidade/page.tsx', content: COMPLIANT_POLICY }])!
    const div = diffPolicyVsCode(doc, operators)
    expect(div.hasInternationalOps).toBe(true)
    expect(div.internationalDisclosed).toBe(true) // §7 declara → sem falso-positivo
    expect(div.undeclaredOperators.map(o => o.name)).toEqual(['OpenAI'])
  })

  it('ignora infra self-hosted na divergência de operadores', () => {
    const doc = findPolicyDoc([{ relPath: 'privacidade/page.tsx', content: COMPLIANT_POLICY }])!
    const div = diffPolicyVsCode(doc, operators)
    expect(div.undeclaredOperators.map(o => o.name)).not.toContain('Banco de dados (self-hosted)')
  })

  it('política silenciosa sobre internacional + ops internacionais no código → não declarada (Art. 33)', () => {
    const doc = findPolicyDoc([{ relPath: 'PRIVACIDADE.md', content: SILENT_ON_INTL_POLICY }])!
    const div = diffPolicyVsCode(doc, [op('Stripe', true), op('AWS', true)])
    expect(div.hasInternationalOps).toBe(true)
    expect(div.internationalDisclosed).toBe(false)
  })
})
