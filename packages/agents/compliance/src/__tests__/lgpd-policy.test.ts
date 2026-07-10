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

// Política que MENTE: NEGA transferência internacional enquanto o código usa Stripe/OpenAI/AWS.
// É o caso MAIS grave e o que a heurística antiga deixava passar (mention≠denial): o termo
// "transferência internacional" aparecia (na negação) → contava como disclosed → escapava.
const DENIES_INTL_POLICY = `
# Política de Privacidade

## Transferência internacional
Não realizamos transferência internacional de dados. Todos os dados dos titulares
permanecem armazenados no Brasil.

## Operadores e base legal
Utilizamos ferramentas de terceiros sob contrato. Base legal: legítimo interesse.
Cookies são usados. A retenção segue os prazos legais. Encarregado (DPO) disponível.
`

// Variante de negação por AFIRMAÇÃO territorial ("dados não saem do Brasil"), sem repetir
// o termo "internacional" — a heurística tem de pegar as duas formas.
const DATA_STAYS_IN_BRAZIL_POLICY = `
# Política de Privacidade

## Onde tratamos seus dados
Os dados dos titulares não são transferidos para fora do Brasil; permanecem no Brasil.

## Operadores e base legal
Terceiros sob contrato. Base legal: consentimento. Cookies. Retenção legal. Encarregado.
`

// Política NUANÇADA e CONFORME (caso real do zap-api): DECLARA a transferência com base no
// Art. 33 E diz que dados SENSÍVEIS permanecem no Brasil. A residência de um subconjunto não é
// negação — citar o Art. 33 como base = está declarando. NÃO pode virar "contradição" (FP).
const NUANCED_ART33_POLICY = `
# Política de Privacidade

## Transferência internacional
Alguns dados são efetivamente transferidos para operadores no exterior. A transferência é
baseada na hipótese do Art. 33, VII da LGPD (necessária para a execução do contrato). Dados
sensíveis e mensagens dos Clientes permanecem no Brasil (Hostinger).

## Operadores e base legal
Terceiros sob contrato. Base legal: legítimo interesse. Cookies. Retenção legal. Encarregado (DPO).
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
    expect(div.internationalDenied).toBe(false) // omissão ≠ negação
  })

  it('FURO DE HONESTIDADE: política que NEGA transferência intl + código a faz → NEGADA, nunca disclosed', () => {
    const doc = findPolicyDoc([{ relPath: 'PRIVACIDADE.md', content: DENIES_INTL_POLICY }])!
    const div = diffPolicyVsCode(doc, [op('Stripe', true), op('OpenAI', true)])
    expect(div.hasInternationalOps).toBe(true)
    // O bug: a negação NÃO pode contar como disclosure (era `true` antes → escapava do check).
    expect(div.internationalDisclosed).toBe(false)
    // E precisa ser marcada como NEGAÇÃO explícita (contradição direta com o código).
    expect(div.internationalDenied).toBe(true)
  })

  it('negação por afirmação territorial ("não saem do Brasil / permanecem no Brasil") também é NEGAÇÃO', () => {
    const doc = findPolicyDoc([{ relPath: 'PRIVACIDADE.md', content: DATA_STAYS_IN_BRAZIL_POLICY }])!
    const div = diffPolicyVsCode(doc, [op('AWS', true)])
    expect(div.internationalDisclosed).toBe(false)
    expect(div.internationalDenied).toBe(true)
  })

  it('GUARD DE RECALL: política que DECLARA honestamente (Art. 33) não é marcada como negação', () => {
    const doc = findPolicyDoc([{ relPath: 'privacidade/page.tsx', content: COMPLIANT_POLICY }])!
    const div = diffPolicyVsCode(doc, operators)
    expect(div.internationalDisclosed).toBe(true)
    expect(div.internationalDenied).toBe(false) // declaração verdadeira não vira falso-positivo de negação
  })

  it('FP do zap-api: DECLARA via Art. 33 + dados sensíveis "permanecem no Brasil" → declarado, NÃO negação', () => {
    const doc = findPolicyDoc([{ relPath: 'legal/privacidade/page.tsx', content: NUANCED_ART33_POLICY }])!
    const div = diffPolicyVsCode(doc, [op('Stripe', true), op('AWS', true)])
    // Citar o Art. 33 como base = declaração; "permanecem no Brasil" (subconjunto) é nuance, não negação.
    expect(div.internationalDenied).toBe(false)
    expect(div.internationalDisclosed).toBe(true)
  })

  it('recall preservado: negação SEM base do Art. 33 continua sendo negação', () => {
    const doc = findPolicyDoc([{ relPath: 'PRIVACIDADE.md', content: DENIES_INTL_POLICY }])!
    const div = diffPolicyVsCode(doc, [op('Stripe', true)])
    expect(div.internationalDenied).toBe(true)
    expect(div.internationalDisclosed).toBe(false)
  })

  // ---- Revisão DPO: completude da política (Art. 41 encarregado / Art. 18 direitos) ----
  it('detecta Encarregado/DPO declarado (Art. 41) e direitos do titular (Art. 18)', () => {
    const full = `# Política de Privacidade
## Operadores
Stripe (pagamento). Base legal: consentimento (Art. 7º). Retenção conforme a lei. Cookies.
## Encarregado
O Encarregado (DPO) pode ser contatado em dpo@exemplo.com.br (Art. 41).
## Direitos do titular
O titular pode solicitar acesso, correção e exclusão dos seus dados, além da portabilidade.
`
    const doc = findPolicyDoc([{ relPath: 'PRIVACIDADE.md', content: full }])!
    const div = diffPolicyVsCode(doc, [op('Stripe', true)])
    expect(div.declaresDpo).toBe(true)
    expect(div.declaresDataSubjectRights).toBe(true)
  })

  it('flagga política SEM Encarregado e SEM direitos do titular (dimensões da revisão DPO)', () => {
    const noDpoNoRights = `# Política de Privacidade
## Operadores e terceiros
Stripe (pagamento), Sentry (erros). Transferência internacional com base no Art. 33.
## Retenção e cookies
Retemos pelo prazo legal. Usamos cookies essenciais. Base legal descrita.
`
    const doc = findPolicyDoc([{ relPath: 'PRIVACIDADE.md', content: noDpoNoRights }])!
    const div = diffPolicyVsCode(doc, [op('Stripe', true)])
    expect(div.declaresDpo).toBe(false)
    expect(div.declaresDataSubjectRights).toBe(false)
  })
})
