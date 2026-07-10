/**
 * Divergência POLÍTICA×CÓDIGO (determinístico, zero-token). O restante do agente já
 * DERIVA do código o que deveria estar na política (operadores/sub-processadores e
 * transferência internacional — Art. 33). Este módulo fecha o laço: localiza a POLÍTICA
 * DE PRIVACIDADE publicada no repositório e confere se ela DECLARA o que o código faz.
 *
 * É a materialização do diferencial LGPD-nativo: não basta apontar "declare na política";
 * aqui a gente confere. Heurístico e CONSERVADOR — na dúvida, considera declarado (evita
 * acusar uma política conforme). Não substitui adequação jurídica.
 */
import type { OperatorMatch } from './lgpd-inventory.js'

export interface PolicyDoc {
  relPath: string
  text: string
}

/** Remove markup JSX/HTML + expressões `{…}` + entidades, deixando só o texto visível. */
export function stripMarkup(s: string): string {
  return s
    .replace(/<[^>]*>/g, ' ') // tags JSX/HTML (com atributos, className etc.)
    .replace(/\{[^{}]{0,120}\}/g, ' ') // interpolações JSX curtas {name} — NÃO o corpo do componente
    .replace(/&[a-z]+;/gi, ' ') // entidades html
    .replace(/\s+/g, ' ')
    .trim()
}

// Assinatura de conteúdo: o documento se declara uma política de privacidade.
const POLICY_TITLE = /pol[ií]tica de privacidade|privacy policy|aviso de privacidade/i
// Path que sugere a página da política.
const POLICY_PATH_HINT = /privac/i
// Sinais de que é o DOCUMENTO (e não um mero link/menção): seções típicas de uma política.
const POLICY_SIGNALS: RegExp[] = [
  /transfer[êe]ncia internacional|internacional/i,
  /base legal|leg[ií]timo interesse|consentimento|art\.?\s*(?:7|9|11|33)\b/i,
  /titular(?:es)?\b/i,
  /reten[çc][ãa]o|prazo/i,
  /operador(?:es)?|sub-?processador|terceiros/i,
  /cookies?/i,
  /encarregad|dpo\b/i,
]

/**
 * Localiza a política de privacidade publicada no repositório entre os arquivos coletados.
 * Pontua candidatos e exige um mínimo de sinais para não confundir um LINK com o documento.
 */
export function findPolicyDoc(files: { relPath: string; content: string }[]): PolicyDoc | null {
  let best: { relPath: string; text: string; score: number } | null = null
  for (const f of files) {
    if (!/\.(tsx|jsx|ts|js|md|mdx|html?)$/i.test(f.relPath)) continue
    const pathHint = POLICY_PATH_HINT.test(f.relPath)
    if (!POLICY_TITLE.test(f.content) && !pathHint) continue

    const text = stripMarkup(f.content)
    if (!POLICY_TITLE.test(text)) continue // o título tem de sobreviver ao strip (texto real, não atributo)

    const signals = POLICY_SIGNALS.reduce((n, re) => n + (re.test(text) ? 1 : 0), 0)
    if (signals < 3) continue // poucos sinais = link/menção, não o documento

    const score = signals + (pathHint ? 2 : 0) + Math.min(3, Math.floor(text.length / 1000))
    if (!best || score > best.score) best = { relPath: f.relPath, text, score }
  }
  return best ? { relPath: best.relPath, text: best.text } : null
}

// Declaração de transferência internacional (Art. 33) na política.
const INTL_DISCLOSURE =
  /transfer[êe]ncia internacional|fora do (?:pa[ií]s|brasil)|outside brazil|other countries|estados unidos|\beua\b|internacional/i

// NEGAÇÃO de transferência internacional. Distingue a política que MENTE ("não realizamos
// transferência internacional", "os dados permanecem no Brasil") daquela que DECLARA. Isto
// fecha o furo de honestidade: antes, a negação casava INTL_DISCLOSURE (contém "internacional")
// e era contada como *declarada* — o caso mais grave escapava. Conservador e ancorado no termo:
// exige a negação/afirmação territorial PERTO do termo, não uma mera menção isolada.
const INTL_DENIAL = new RegExp(
  [
    // "não" + (até ~30 chars, aceita acentos via [\s\S]) + termo de transferência ao exterior
    'n[ãa]o[\\s\\S]{0,30}?(?:transfer[êe]ncia\\s+internacional|transfer\\w*\\b[\\s\\S]{0,20}?(?:exterior|fora do (?:pa[ií]s|brasil)))',
    // afirmação territorial: os dados permanecem/ficam/são mantidos/armazenados/hospedados NO Brasil
    '(?:permanec\\w+|fica\\w*|mantid\\w+|armazenad\\w+|hospedad\\w+)[\\s\\S]{0,25}?(?:no|em)\\s+brasil',
  ].join('|'),
  'i',
)

// Sinônimos por operador (canônico = OperatorMatch.name), em minúsculas, para casar na política.
// Conservador: qualquer sinônimo presente = considerado declarado (evita falso-positivo).
const OPERATOR_SYNONYMS: Record<string, string[]> = {
  AWS: ['aws', 'amazon web services', 'amazon'],
  'Google Cloud/Firebase': ['google', 'firebase', 'gcp', 'google cloud'],
  'Microsoft Azure': ['azure', 'microsoft'],
  Stripe: ['stripe'],
  OpenAI: ['openai', 'open ai', 'chatgpt', 'gpt-'],
  Anthropic: ['anthropic', 'claude'],
  Sentry: ['sentry'],
  'Analytics (PostHog/Mixpanel/Segment/Amplitude)': ['posthog', 'mixpanel', 'segment', 'amplitude', 'analytics'],
  Supabase: ['supabase'],
  Vercel: ['vercel'],
  'E-mail transacional (Resend/SendGrid/Mailgun/Postmark)': ['resend', 'sendgrid', 'mailgun', 'postmark', 'mail transacional', 'e-mail transacional'],
  Twilio: ['twilio'],
  Cloudinary: ['cloudinary'],
  Datadog: ['datadog'],
  Upstash: ['upstash'],
  'Mercado Pago': ['mercado pago', 'mercadopago'],
}

// Operadores que NÃO são sub-processadores de terceiros a declarar (infra self-hosted/nacional).
const NOT_A_SUBPROCESSOR = new Set(['Banco de dados (self-hosted)'])

// Encarregado/DPO (Art. 41) declarado na política.
const POLICY_DPO = /encarregad|\bdpo\b|data protection officer/i
// Direitos do titular (Art. 18) declarados na política. Conservador (na dúvida = declarado):
// qualquer sinal claro de exercício de direitos conta, para não acusar política conforme.
const POLICY_RIGHTS =
  /direitos?\s+d[oe]s?\s+titular|direito\s+de\s+(acesso|corre|exclus|elimin|portabil)|(solicitar|exercer|revogar)[\s\S]{0,40}(acesso|corre[çc]|exclus|elimin|portabil|consentimento)|portabilidade\s+d[oe]s?\s+dados|anonimiza[çc][ãa]o/i

export interface PolicyDivergence {
  policyPath: string
  hasInternationalOps: boolean
  /** A política DECLARA transferência internacional (menção real, não uma negação). */
  internationalDisclosed: boolean
  /** A política NEGA transferência internacional ("não realizamos…", "permanecem no Brasil"). */
  internationalDenied: boolean
  undeclaredOperators: OperatorMatch[]
  /** A política declara o Encarregado/DPO e canal de contato (Art. 41). */
  declaresDpo: boolean
  /** A política declara os direitos do titular / como exercê-los (Art. 18). */
  declaresDataSubjectRights: boolean
}

/** Confere a política publicada contra os operadores/transferências que o código revela. */
export function diffPolicyVsCode(policy: PolicyDoc, operators: OperatorMatch[]): PolicyDivergence {
  const text = policy.text.toLowerCase()
  const mentionsIntl = INTL_DISCLOSURE.test(policy.text)
  const deniesIntl = INTL_DENIAL.test(policy.text)
  // Uma política que cita o Art. 33 (a base legal DA transferência internacional) está
  // DECLARANDO/justificando a transferência, não negando. Desambigua o caso nuançado e conforme
  // (real: zap-api) "transferimos sob a hipótese do Art. 33, mas dados sensíveis permanecem no
  // Brasil" — a residência de um SUBCONJUNTO ("permanecem no Brasil") casaria INTL_DENIAL, mas
  // não é negação da transferência. Conservador (na dúvida, declarado): evita FP em política conforme.
  const citesArt33Basis = /art\.?\s*33/i.test(policy.text)
  // Uma NEGAÇÃO nunca conta como disclosure — mas só é negação se NÃO houver também a declaração
  // via Art. 33. Este é o coração do fix: mention (inclusive na negação) ≠ declaração honesta;
  // porém declaração explícita (Art. 33) vence a nuance territorial.
  const internationalDenied = deniesIntl && !(mentionsIntl && citesArt33Basis)
  const internationalDisclosed = mentionsIntl && !internationalDenied
  const hasInternationalOps = operators.some(o => o.international)

  const undeclaredOperators: OperatorMatch[] = []
  for (const op of operators) {
    if (NOT_A_SUBPROCESSOR.has(op.name)) continue
    const syns = OPERATOR_SYNONYMS[op.name] ?? [op.name.toLowerCase()]
    const declared = syns.some(s => text.includes(s))
    if (!declared) undeclaredOperators.push(op)
  }

  return {
    policyPath: policy.relPath, hasInternationalOps, internationalDisclosed, internationalDenied, undeclaredOperators,
    declaresDpo: POLICY_DPO.test(policy.text),
    declaresDataSubjectRights: POLICY_RIGHTS.test(policy.text),
  }
}
