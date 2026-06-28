import type { AuditReport, Finding, ProposedFix, ReportEnricher } from '@fracta/core'

/** Abstração mínima do provedor LLM — injetável para testes (sem rede). */
export interface LlmClient {
  complete(input: { model: string; system: string; user: string; maxTokens: number }): Promise<string>
}

export interface LlmEnricherOptions {
  apiKey?: string
  model?: string
  /** Cliente injetável (testes). Se ausente, usa o SDK Anthropic quando há apiKey. */
  client?: LlmClient
  verbose?: boolean
}

const DEFAULT_MODEL = 'claude-opus-4-8'

const SYSTEM_PROMPT = `Você é a borda de priorização do Fracta, um auditor de segurança.
Os achados (findings) JÁ foram detectados de forma determinística por ferramentas. Seu papel é ESTRITO:
1. PRIORIZAR: ordenar os achados por "o que resolver primeiro neste SaaS hoje", considerando severidade, regressão e o perfil do produto.
2. REDIGIR correção: para achados sem correção proposta, escrever uma remediação acionável.

PROIBIÇÕES ABSOLUTAS:
- NÃO invente achados nem remova achados. Use apenas os ids fornecidos.
- NÃO decida se algo é vulnerável (isso é da ferramenta).
- NÃO altere a severidade de nenhum achado.
- NÃO aplique nenhuma correção — apenas descreva.
- "riskOfApplying" é OBRIGATÓRIO e honesto: o que pode quebrar se a correção for aplicada.

Responda SOMENTE com JSON válido, sem texto fora do JSON, neste formato:
{
  "order": ["<id>", "..."],            // ids fornecidos, em ordem de prioridade
  "rationale": "<por que esta ordem>",
  "fixes": [
    { "id": "<id>", "description": "<remediação acionável>", "command": "<opcional>", "diff": "<opcional>", "riskOfApplying": "<o que pode quebrar>" }
  ]
}`

interface ModelOutput {
  order?: unknown
  rationale?: unknown
  fixes?: unknown
}

/**
 * Borda LLM do Fracta (Fase 6). Prioriza achados e redige correções gated.
 * Desligado (no-op) quando não há API key nem cliente injetado — a detecção
 * NUNCA depende disto. Nunca inventa/remove achados nem muda severidade.
 */
export class LlmEnricher implements ReportEnricher {
  private readonly client?: LlmClient
  private readonly model: string
  private readonly verbose: boolean

  constructor(opts: LlmEnricherOptions = {}) {
    this.model = opts.model ?? process.env.FRACTA_LLM_MODEL ?? DEFAULT_MODEL
    this.verbose = opts.verbose ?? false
    if (opts.client) {
      this.client = opts.client
    } else {
      const apiKey = opts.apiKey ?? process.env.ANTHROPIC_API_KEY
      this.client = apiKey ? createAnthropicClient(apiKey) : undefined
    }
  }

  /** true se há um provedor configurado (API key ou cliente injetado). */
  get enabled(): boolean {
    return !!this.client
  }

  async enrich(report: AuditReport): Promise<AuditReport> {
    if (!this.client || report.findings.length === 0) return report

    const raw = await this.client.complete({
      model: this.model,
      system: SYSTEM_PROMPT,
      user: buildUserPrompt(report),
      maxTokens: 8000,
    })

    const parsed = parseModelJson(raw)
    if (!parsed) {
      if (this.verbose) console.error('[Fracta] LLM: resposta não interpretável; mantendo relatório determinístico')
      return report
    }

    return applyEnrichment(report, parsed)
  }
}

function buildUserPrompt(report: AuditReport): string {
  const findings = report.findings.map(f => ({
    id: f.id,
    camada: f.camada ?? f.category,
    severidade: f.severity,
    status: f.status ?? 'open',
    titulo: f.title,
    achado: truncate(f.description, 500),
    evidencia: f.evidence ? truncate(f.evidence, 300) : undefined,
    temCorrecao: !!f.proposedFix,
  }))
  return `SaaS: ${report.saas}\nRegressões: ${report.resumo.regressoes}\n\nAchados:\n${JSON.stringify(findings, null, 2)}`
}

/**
 * Aplica a saída do modelo ao relatório de forma defensiva (lógica pura, testável):
 * - prioritization.order = ids válidos na ordem do modelo + restantes preservando a ordem atual
 * - proposedFix só é preenchido onde NÃO existe ainda (não sobrescreve correção determinística)
 *   e somente quando description + riskOfApplying estão presentes
 * - severidade e conjunto de achados permanecem intactos
 */
export function applyEnrichment(report: AuditReport, output: ModelOutput): AuditReport {
  const known = new Map(report.findings.map(f => [f.id, f]))

  const requested = Array.isArray(output.order) ? output.order.filter((x): x is string => typeof x === 'string') : []
  const seen = new Set<string>()
  const order: string[] = []
  for (const id of requested) {
    if (known.has(id) && !seen.has(id)) {
      seen.add(id)
      order.push(id)
    }
  }
  // Achados não citados pelo modelo entram no fim, preservando a ordem atual.
  for (const f of report.findings) {
    if (!seen.has(f.id)) order.push(f.id)
  }

  const fixesById = new Map<string, ProposedFix>()
  if (Array.isArray(output.fixes)) {
    for (const raw of output.fixes) {
      if (!raw || typeof raw !== 'object') continue
      const fix = raw as Record<string, unknown>
      const id = typeof fix.id === 'string' ? fix.id : undefined
      const description = typeof fix.description === 'string' ? fix.description : undefined
      const riskOfApplying = typeof fix.riskOfApplying === 'string' ? fix.riskOfApplying : undefined
      if (!id || !description || !riskOfApplying || !known.has(id)) continue
      const proposed: ProposedFix = { description, riskOfApplying }
      if (typeof fix.command === 'string') proposed.command = fix.command
      if (typeof fix.diff === 'string') proposed.diff = fix.diff
      fixesById.set(id, proposed)
    }
  }

  const findings: Finding[] = report.findings.map(f => {
    // Só preenche onde não há correção determinística (não sobrescreve).
    if (!f.proposedFix && fixesById.has(f.id)) {
      return { ...f, proposedFix: fixesById.get(f.id) }
    }
    return f
  })

  const rationale = typeof output.rationale === 'string' ? output.rationale : undefined

  return {
    ...report,
    findings,
    prioritization: { order, rationale },
  }
}

/** Extrai o primeiro objeto JSON de uma resposta (tolera cercas ```json e texto ao redor). */
export function parseModelJson(raw: string): ModelOutput | null {
  if (!raw) return null
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i)
  const candidate = fenced ? fenced[1] : raw
  const start = candidate.indexOf('{')
  const end = candidate.lastIndexOf('}')
  if (start === -1 || end === -1 || end <= start) return null
  try {
    const obj = JSON.parse(candidate.slice(start, end + 1))
    return obj && typeof obj === 'object' ? (obj as ModelOutput) : null
  } catch {
    return null
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s
}

function createAnthropicClient(apiKey: string): LlmClient {
  return {
    async complete({ model, system, user, maxTokens }) {
      // Import dinâmico: o SDK só é carregado quando a borda LLM é realmente usada.
      const mod = await import('@anthropic-ai/sdk')
      const Anthropic = mod.default
      const client = new Anthropic({ apiKey })
      const resp = await client.messages.create({
        model,
        max_tokens: maxTokens,
        system,
        messages: [{ role: 'user', content: user }],
      })
      const blocks = resp.content as unknown as Array<{ type: string; text?: string }>
      return blocks
        .filter(b => b.type === 'text')
        .map(b => b.text ?? '')
        .join('\n')
    },
  }
}
