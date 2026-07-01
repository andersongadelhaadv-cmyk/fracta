/**
 * LGPD ancorada no CÓDIGO (determinístico, zero-token): lê o schema Prisma para montar
 * um inventário de dados pessoais (rascunho de ROPA) e as dependências para mapear
 * operadores/sub-processadores + transferência internacional (Art. 33). Heurístico e
 * rotulado — não substitui adequação jurídica, mas automatiza os 80% investigativos.
 */

export type DataCategory = 'sensivel' | 'pessoal' | 'comum'

// Dado sensível/alto risco no contexto (Art. 5º, II + domínio jurídico/previdenciário BR).
const SENSITIVE_FIELD =
  /(cpf|cnpj|cnis|\brg\b|senha|password|passwd|hash|secret|processo|prontuario|prontuário|\bnis\b|\bpis\b|cart[aã]o|benef[ií]cio|sa[uú]de|health|biometr|digital|genetic|gen[eé]tico|racial|etnia|religi|orienta[cç][aã]o|sexual|criminal|diagn[oó]stico)/i

// Dado pessoal comum.
const PERSONAL_FIELD =
  /(nome|\bname\b|email|e-mail|\bmail\b|telefone|phone|celular|whatsapp|endere[cç]o|address|logradouro|\bcep\b|nascimento|birth|\bdob\b|\bidade\b|g[eê]nero|gender|foto|avatar|\bip\b|geoloc|latitude|longitude|documento|passaporte|matr[ií]cula)/i

export function classifyField(fieldName: string): DataCategory {
  if (SENSITIVE_FIELD.test(fieldName)) return 'sensivel'
  if (PERSONAL_FIELD.test(fieldName)) return 'pessoal'
  return 'comum'
}

export interface PrismaModel {
  model: string
  fields: string[]
}

/** Parseia blocos `model X { ... }` do schema Prisma → nome do modelo + nomes de campo. */
export function parsePrismaModels(schema: string): PrismaModel[] {
  const models: PrismaModel[] = []
  const modelRe = /model\s+(\w+)\s*\{([\s\S]*?)\}/g
  let m: RegExpExecArray | null
  while ((m = modelRe.exec(schema)) !== null) {
    const name = m[1]
    const body = m[2]
    const fields: string[] = []
    for (const line of body.split(/\r?\n/)) {
      const t = line.trim()
      if (!t || t.startsWith('//') || t.startsWith('@@')) continue // comentário/atributo de bloco
      const field = t.split(/\s+/)[0]
      if (/^\w+$/.test(field)) fields.push(field)
    }
    models.push({ model: name, fields })
  }
  return models
}

export interface InventoryEntry {
  model: string
  sensivel: string[]
  pessoal: string[]
}

/** Inventário: modelos que contêm dado pessoal, com os campos classificados. */
export function buildInventory(models: PrismaModel[]): InventoryEntry[] {
  const out: InventoryEntry[] = []
  for (const m of models) {
    const sensivel: string[] = []
    const pessoal: string[] = []
    for (const f of m.fields) {
      const c = classifyField(f)
      if (c === 'sensivel') sensivel.push(f)
      else if (c === 'pessoal') pessoal.push(f)
    }
    if (sensivel.length || pessoal.length) out.push({ model: m.model, sensivel, pessoal })
  }
  return out
}

export interface OperatorMatch {
  name: string
  purpose: string
  international: boolean
}

// Dicionário de operadores/sub-processadores comuns (por pacote npm).
const OPERATORS: Array<{ re: RegExp; name: string; purpose: string; international: boolean }> = [
  { re: /^@?aws-sdk|^aws-sdk|^@aws-/, name: 'AWS', purpose: 'infraestrutura/cloud', international: true },
  { re: /^@google-cloud\/|^googleapis$|^firebase/, name: 'Google Cloud/Firebase', purpose: 'infraestrutura/cloud', international: true },
  { re: /^@azure\/|^@azure-/, name: 'Microsoft Azure', purpose: 'infraestrutura/cloud', international: true },
  { re: /^stripe$/, name: 'Stripe', purpose: 'pagamentos', international: true },
  { re: /^@?openai$|^openai$/, name: 'OpenAI', purpose: 'IA generativa (conteúdo do usuário)', international: true },
  { re: /^@anthropic-ai\//, name: 'Anthropic', purpose: 'IA generativa (conteúdo do usuário)', international: true },
  { re: /^@sentry\//, name: 'Sentry', purpose: 'monitoramento de erros', international: true },
  { re: /^@?posthog|^mixpanel|^@segment\/|^amplitude/, name: 'Analytics (PostHog/Mixpanel/Segment/Amplitude)', purpose: 'analytics/comportamento', international: true },
  { re: /^@supabase\//, name: 'Supabase', purpose: 'backend/banco de dados', international: true },
  { re: /^@vercel\//, name: 'Vercel', purpose: 'hospedagem/edge', international: true },
  { re: /^resend$|^@sendgrid\/|^mailgun|^nodemailer$|^postmark/, name: 'E-mail transacional (Resend/SendGrid/Mailgun/Postmark)', purpose: 'e-mail transacional', international: true },
  { re: /^twilio$/, name: 'Twilio', purpose: 'SMS/comunicação', international: true },
  { re: /^cloudinary$|^@cloudinary\//, name: 'Cloudinary', purpose: 'mídia/storage', international: true },
  { re: /^@datadog\/|^dd-trace$/, name: 'Datadog', purpose: 'observabilidade', international: true },
  { re: /^@upstash\//, name: 'Upstash', purpose: 'cache/fila (Redis/Kafka)', international: true },
  { re: /^@?mercadopago|^mercadopago/, name: 'Mercado Pago', purpose: 'pagamentos', international: false },
  { re: /^pg$|^mysql2?$|^prisma$|^@prisma\/|^mongoose$|^redis$|^ioredis$/, name: 'Banco de dados (self-hosted)', purpose: 'persistência', international: false },
]

/** Mapeia dependências (deps + devDeps) → operadores/sub-processadores conhecidos. */
export function detectOperators(packageJsonText: string): OperatorMatch[] {
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
  try {
    pkg = JSON.parse(packageJsonText)
  } catch {
    return []
  }
  const names = new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})])
  const seen = new Map<string, OperatorMatch>()
  for (const dep of names) {
    for (const op of OPERATORS) {
      if (op.re.test(dep)) {
        if (!seen.has(op.name)) seen.set(op.name, { name: op.name, purpose: op.purpose, international: op.international })
      }
    }
  }
  return Array.from(seen.values())
}
