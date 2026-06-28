import { randomUUID, createHash } from 'crypto'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/** Status de um Finding entre execuções (ver regressão/supressão na Fase 2). */
export type FindingStatus = 'open' | 'suppressed' | 'regression'

export type AgentCategory =
  | 'security'
  | 'docs'
  | 'code'
  | 'deps'
  | 'secrets'
  | 'infra'
  | 'compliance'
  | 'performance'

export type StackType = string

export const KNOWN_STACKS = [
  'nestjs', 'nextjs', 'prisma', 'stripe', 'supabase',
  'whatsapp', 'redis', 'docker',
] as const

export type ScanDepth = 'quick' | 'full' | 'paranoid'

export interface TargetAuth {
  type: 'jwt' | 'apikey' | 'basic' | 'oauth'
  endpoint?: string
  credentials?: {
    email?: string
    password?: string
    apiKey?: string
  }
  headerName?: string
  headerPrefix?: string
}

/** Acesso a infra de um alvo (opcional — ausência → checks de infra ficam `skipped`). */
export interface TargetInfra {
  host?: string
  sshConfigPath?: string
  dockerComposePath?: string
}

export interface TargetFrontend {
  framework: 'next' | 'react' | 'none'
  envFiles?: string[]
}

export interface TargetConfig {
  /** IDs de findings já revisados como falso-positivo (ver Fase 2). */
  suppressions?: string[]
  severityThreshold?: Severity
}

export interface Target {
  name: string
  url: string
  stack: StackType[]
  auth?: TargetAuth
  agents?: string[]
  skills?: string[]
  ignore?: string[]
  /** Caminho local do repositório clonado (para agentes baseados em repo/SAST). */
  repoPath?: string
  infra?: TargetInfra
  frontend?: TargetFrontend
  config?: TargetConfig
}

/**
 * Correção PROPOSTA por um agente/LLM. NUNCA aplicada automaticamente (regra 2/6).
 * `riskOfApplying` é obrigatório: honestidade sobre o que pode quebrar.
 */
export interface ProposedFix {
  description: string
  diff?: string
  command?: string
  riskOfApplying: string
}

export interface Finding {
  id: string
  runId: string
  agent: string
  category: AgentCategory
  /** Camada de auditoria. Default = `category` quando o agente não distingue. */
  camada?: AgentCategory
  severity: Severity
  /** Estado entre execuções. Preenchido pelo store na Fase 2; default `open`. */
  status?: FindingStatus
  title: string
  description: string
  endpoint?: string
  evidence?: string
  recommendation: string
  /** Correção gated, opcional — preenchida pela borda LLM (Fase 6). */
  proposedFix?: ProposedFix
  references?: string[]
  createdAt: Date
}

export interface ScanScope {
  target: Target
  depth: ScanDepth
  agents: string[]
  runId: string
  startedAt: Date
  /** Saúde do alvo medida no preflight (Fase 3). Agentes podem consultar p/ decidir skip. */
  health?: TargetHealth
}

export interface ScanReport {
  runId: string
  target: string
  startedAt: Date
  finishedAt: Date
  durationMs: number
  summary: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  findings: Finding[]
  passed: boolean
}

export interface SecurityAgent {
  name: string
  category: AgentCategory
  concurrency: number
  timeoutMs: number
  run(scope: ScanScope): Promise<Finding[]>
}

export interface HttpResponse {
  status: number
  headers: Record<string, string>
  body: unknown
  raw: string
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  headers?: Record<string, string>
  body?: unknown
  timeoutMs?: number
}

export interface SecurityTest {
  name: string
  path: string
  method: RequestOptions['method']
  headers?: Record<string, string>
  body?: unknown
  expect: (response: HttpResponse) => Finding[]
}

export interface FractaSkill {
  name: string
  targets: StackType[]
  detect(target: Target): boolean
  getTests(): SecurityTest[]
  evaluate(response: HttpResponse): Finding[]
}

export function makeFinding(
  partial: Omit<Finding, 'id' | 'createdAt'>
): Finding {
  return {
    ...partial,
    id: randomUUID(),
    createdAt: new Date(),
  }
}

/**
 * Hash estável e determinístico para o `id` de um Finding.
 * Mesmo achado → sempre o mesmo id. É o que faz regressão e supressão funcionarem (Fase 2).
 * Derivado de `saas + camada + regra + localização normalizada`.
 */
export function stableFindingId(parts: {
  saas: string
  camada: string
  rule: string
  location?: string
}): string {
  const key = [
    parts.saas.trim().toLowerCase(),
    parts.camada.trim().toLowerCase(),
    parts.rule.trim().toLowerCase(),
    (parts.location ?? '').trim().toLowerCase(),
  ].join('|')
  return createHash('sha256').update(key).digest('hex').slice(0, 16)
}

/**
 * Sinaliza que um check não rodou por falta de input (sem repoPath, stack incompatível,
 * staging não fornecido...). O orquestrador transforma em `CheckResult.status = 'skipped'`.
 * "Não verificado" ≠ "seguro". Qualquer outro throw vira `status: 'error'`.
 */
export class SkippedCheck extends Error {
  constructor(public readonly motivo: string) {
    super(motivo)
    this.name = 'SkippedCheck'
  }
}

export type CheckStatus = 'ok' | 'error' | 'skipped'

/** Resultado isolado de UM agente. Um check nunca derruba os outros (regra 4). */
export interface CheckResult {
  agent: string
  camada: AgentCategory
  status: CheckStatus
  /** Motivo quando status é `error` ou `skipped`. */
  motivo?: string
  durationMs: number
  findings: Finding[]
}

/**
 * Veredito honesto de uma auditoria:
 * - `failed`: há achado de severidade que dispara `failOn` (problema concreto).
 * - `inconclusive`: nada falhou, MAS a auditoria não conseguiu exercer o alvo
 *   (ex.: target `unreachable` → a camada DAST nunca rodou). "Não verificado" ≠ "seguro".
 * - `passed`: o alvo foi exercido e nenhum achado dispara `failOn`.
 */
export type Verdict = 'passed' | 'failed' | 'inconclusive'

export type TargetHealthStatus = 'healthy' | 'degraded' | 'unreachable'

export interface TargetHealth {
  repoAccessible: boolean
  stagingResponding?: boolean
  vpsReachable?: boolean
  status: TargetHealthStatus
}

/**
 * Porta de persistência entre execuções (regressão/supressão). O core define o
 * contrato; a implementação concreta (SQLite) vive em `@fracta/store` e é injetada
 * pelo cli/mcp — assim o core não depende de nenhum backend de armazenamento.
 */
export interface FindingStore {
  /**
   * Define `status` de cada finding com base no histórico:
   * - id em `suppressions` → `suppressed`
   * - id que existia e havia sido resolvido/ausente, e voltou → `regression`
   * - id inédito ou já aberto → `open`
   * Persiste o histórico (firstSeen/lastSeen/resolved). Retorna os findings com status.
   */
  applyStatus(
    saas: string,
    findings: Finding[],
    suppressions: string[],
  ): Finding[] | Promise<Finding[]>
  /** Persiste o run completo (para painel/comparação futura). */
  recordRun(report: AuditReport): void | Promise<void>
}

/**
 * Priorização produzida pela borda LLM (Fase 6) — ordem de finding ids "o que
 * resolver primeiro" + racional. Não altera severidade nem o conjunto de findings.
 */
export interface Prioritization {
  order: string[]
  rationale?: string
}

/**
 * Relatório consolidado de uma auditoria de UM SaaS. Superset de `ScanReport`
 * (mantém os campos antigos para compatibilidade) + camada de robustez.
 */
export interface AuditReport extends ScanReport {
  saas: string
  timestamp: string
  targetHealth: TargetHealth
  /**
   * Veredito honesto (passed/failed/inconclusive). Sempre preenchido pelo
   * orquestrador. Opcional no tipo para retrocompatibilidade com relatórios
   * antigos; consumidores caem em `passed` quando ausente.
   */
  verdict?: Verdict
  checks: CheckResult[]
  resumo: {
    porSeveridade: Record<Severity, number>
    regressoes: number
    checksComErro: string[]
    checksPulados: string[]
  }
  /** Preenchido pela borda LLM, se habilitada (opcional). */
  prioritization?: Prioritization
}

/**
 * Pós-processamento opcional do relatório pela borda LLM. Implementação concreta
 * em `@fracta/llm`, injetada pelo cli/mcp. A detecção NUNCA depende disto — se o
 * enricher falhar ou não houver API key, o relatório determinístico segue intacto.
 */
export interface ReportEnricher {
  enrich(report: AuditReport): Promise<AuditReport>
}
