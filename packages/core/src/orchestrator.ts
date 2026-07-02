import { randomUUID } from 'crypto'
import {
  SkippedCheck,
} from './types.js'
import { checkTargetHealth } from './health.js'
import { applyConfidence } from './confidence.js'
import type {
  Target, SecurityAgent, AuditReport, ScanScope, Finding, Severity,
  ScanDepth, CheckResult, AgentCategory, TargetHealth, FindingStore, ReportEnricher, Verdict,
} from './types.js'

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

/**
 * Veredito honesto a partir do resumo + saúde do alvo + estado dos checks
 * (lógica pura, testável).
 * - Achado de severidade `failOn` presente → `failed` (problema concreto vence).
 * - Senão, alvo `unreachable` → `inconclusive`: a camada testável (DAST) nunca
 *   exerceu o alvo, então "0 achados" NÃO é "seguro" (regra de honestidade).
 * - Senão, algum check CRASHOU (status `error`) → `inconclusive`: aquela dimensão
 *   não foi medida, então não pode conviver com "✅ PASSOU" no topo (#26 / 🧭-A).
 *   Um check `skipped` (pulado por design, ex.: agente repo-only sem repoPath) NÃO
 *   rebaixa — só o `error` (anomalia: tentou medir e quebrou).
 * - Senão → `passed`.
 */
export function deriveVerdict(
  summary: Record<Severity, number>,
  failOn: Severity[],
  health: TargetHealth,
  checks: CheckResult[] = [],
): Verdict {
  if (failOn.some(s => summary[s] > 0)) return 'failed'
  if (health.status === 'unreachable') return 'inconclusive'
  if (checks.some(c => c.status === 'error')) return 'inconclusive'
  return 'passed'
}

export interface OrchestratorOptions {
  concurrency?: number
  failOn?: Severity[]
  depth?: ScanDepth
  verbose?: boolean
  /** Persistência opcional para regressão/supressão (injetada pelo cli/mcp). */
  store?: FindingStore
  /** Preflight de saúde do alvo. Default: checkTargetHealth. Injetável p/ testes. */
  healthCheck?: (target: Target) => Promise<TargetHealth>
  /** Borda LLM opcional (prioriza + redige correções). Detecção não depende dela. */
  enricher?: ReportEnricher
}

export class FractaOrchestrator {
  private agents: SecurityAgent[] = []
  private readonly options: Required<Omit<OrchestratorOptions, 'store' | 'healthCheck' | 'enricher'>>
  private readonly store?: FindingStore
  private readonly healthCheck: (target: Target) => Promise<TargetHealth>
  private readonly enricher?: ReportEnricher

  constructor(options: OrchestratorOptions = {}) {
    this.options = {
      concurrency: options.concurrency ?? 3,
      failOn: options.failOn ?? ['critical', 'high'],
      depth: options.depth ?? 'full',
      verbose: options.verbose ?? false,
    }
    this.store = options.store
    this.healthCheck = options.healthCheck ?? checkTargetHealth
    this.enricher = options.enricher
  }

  registerAgent(agent: SecurityAgent): this {
    this.agents.push(agent)
    return this
  }

  registerAgents(agents: SecurityAgent[]): this {
    agents.forEach(a => this.registerAgent(a))
    return this
  }

  async scan(target: Target): Promise<AuditReport> {
    const runId = randomUUID()
    const startedAt = new Date()

    const activeAgents = target.agents && target.agents.length > 0
      ? this.agents.filter(a => target.agents!.includes(a.name))
      : this.agents

    if (this.options.verbose) {
      console.log(`\n[Fracta] Scanning: ${target.name} (${target.url})`)
      console.log(`[Fracta] Agents: ${activeAgents.map(a => a.name).join(', ')}`)
      console.log(`[Fracta] Depth: ${this.options.depth}`)
    }

    // Preflight de saúde (Fase 3): nunca tratar alvo fora do ar como "seguro".
    const health = await this.healthCheck(target)
    if (target.repoPath && !health.repoAccessible) {
      // Repo obrigatório inacessível: não há o que auditar → aborta esta auditoria.
      // NÃO persiste (evita marcar todo o histórico como resolvido por engano).
      return this.buildAbortedReport(target, runId, startedAt, health)
    }

    const scope: ScanScope = {
      target,
      depth: this.options.depth,
      agents: activeAgents.map(a => a.name),
      runId,
      startedAt,
      health,
    }

    // Cada agente roda ISOLADO: timeout + try/catch → CheckResult. Um check
    // nunca derruba os outros (regra 4). Concorrência limitada por chunks.
    const checks: CheckResult[] = []
    const chunks = chunkArray(activeAgents, this.options.concurrency)
    for (const chunk of chunks) {
      const results = await Promise.all(chunk.map(a => this.runCheckIsolated(a, scope)))
      checks.push(...results)
    }

    let findings: Finding[] = checks.flatMap(c => c.findings)

    // Estado entre execuções: marca regressão/supressão a partir do histórico.
    // Falha de persistência NUNCA derruba a detecção — degrada para status 'open'.
    if (this.store) {
      try {
        const suppressions = target.config?.suppressions ?? []
        findings = await this.store.applyStatus(target.name, findings, suppressions)
      } catch (err) {
        if (this.options.verbose) console.error(`[Fracta] Store.applyStatus falhou: ${String(err)}`)
      }
    }

    // Camada de VERIFICAÇÃO (Fase 2): atribui/rebaixa confiança por contexto (FP-prone).
    findings = applyConfidence(findings)
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

    // `summary` = exibição (todos os não-suprimidos). `failSummary` = decisão de pass/fail
    // (só achados de confiança ≥ média; heurístico/FP-prone AVISA, não derruba o build).
    // Suprimidos (falso-positivo revisado) ficam fora de ambos, mas seguem em `findings`.
    const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    const failSummary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      if (f.status === 'suppressed') continue
      summary.total++
      summary[f.severity]++
      if (f.confidence !== 'low') {
        failSummary.total++
        failSummary[f.severity]++
      }
    }

    const finishedAt = new Date()
    const verdict = deriveVerdict(failSummary, this.options.failOn, health, checks)
    const passed = verdict === 'passed'

    const targetHealth: TargetHealth = health

    let report: AuditReport = {
      runId,
      target: target.name,
      startedAt,
      finishedAt,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      summary,
      findings,
      passed,
      saas: target.name,
      timestamp: finishedAt.toISOString(),
      targetHealth,
      verdict,
      checks,
      resumo: {
        porSeveridade: {
          critical: summary.critical,
          high: summary.high,
          medium: summary.medium,
          low: summary.low,
          info: summary.info,
        },
        regressoes: findings.filter(f => f.status === 'regression').length,
        checksComErro: checks.filter(c => c.status === 'error').map(c => c.agent),
        checksPulados: checks.filter(c => c.status === 'skipped').map(c => c.agent),
      },
    }

    // Borda LLM (opcional, último passo): prioriza + redige correções. Falha aqui
    // NUNCA derruba a detecção — degrada para o relatório determinístico.
    if (this.enricher) {
      try {
        report = await this.enricher.enrich(report)
      } catch (err) {
        if (this.options.verbose) console.error(`[Fracta] Enricher falhou: ${String(err)}`)
      }
    }

    if (this.store) {
      try {
        await this.store.recordRun(report)
      } catch (err) {
        if (this.options.verbose) console.error(`[Fracta] Store.recordRun falhou: ${String(err)}`)
      }
    }

    this.printSummary(report)
    return report
  }

  async scanAll(targets: Target[]): Promise<AuditReport[]> {
    const reports: AuditReport[] = []
    for (const target of targets) {
      reports.push(await this.scan(target))
    }
    return reports
  }

  /**
   * Executa UM agente de forma isolada: aplica timeout, captura qualquer falha
   * e devolve sempre um CheckResult (ok | error | skipped). Nunca propaga exceção.
   */
  private async runCheckIsolated(agent: SecurityAgent, scope: ScanScope): Promise<CheckResult> {
    const camada: AgentCategory = agent.category
    const start = Date.now()
    try {
      const findings = await withTimeout(agent.run(scope), agent.timeoutMs)
      return {
        agent: agent.name,
        camada,
        status: 'ok',
        durationMs: Date.now() - start,
        findings: findings.map(f => normalizeFinding(f, camada)),
      }
    } catch (err) {
      const durationMs = Date.now() - start
      if (err instanceof SkippedCheck) {
        return { agent: agent.name, camada, status: 'skipped', motivo: err.motivo, durationMs, findings: [] }
      }
      const motivo = err instanceof Error ? err.message : String(err)
      if (this.options.verbose) console.error(`[Fracta] Check error (${agent.name}): ${motivo}`)
      return { agent: agent.name, camada, status: 'error', motivo, durationMs, findings: [] }
    }
  }

  /**
   * Auditoria abortada por repo obrigatório inacessível. Devolve um AuditReport
   * honesto (nenhum check rodou, não passou) sem persistir nada.
   */
  private buildAbortedReport(
    target: Target,
    runId: string,
    startedAt: Date,
    health: TargetHealth,
  ): AuditReport {
    const finishedAt = new Date()
    const motivo = `repoPath inacessível ou não é um repositório git válido: ${target.repoPath}`
    console.error(`\n[Fracta] ${target.name} — ⛔ AUDITORIA ABORTADA: ${motivo}`)
    return {
      runId,
      target: target.name,
      startedAt,
      finishedAt,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings: [],
      passed: false,
      saas: target.name,
      timestamp: finishedAt.toISOString(),
      targetHealth: health,
      // Repo obrigatório inacessível: não foi possível auditar → inconclusivo, não "falhou".
      verdict: 'inconclusive',
      checks: [],
      resumo: {
        porSeveridade: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        regressoes: 0,
        checksComErro: [],
        checksPulados: [],
      },
    }
  }

  private printSummary(report: AuditReport): void {
    const status = report.verdict === 'inconclusive'
      ? '⚠️ INCONCLUSIVE (alvo não exercido)'
      : report.passed ? '✅ PASSED' : '❌ FAILED'
    console.log(`\n[Fracta] ${report.target} — ${status}`)
    console.log(`  Critical: ${report.summary.critical}  High: ${report.summary.high}  Medium: ${report.summary.medium}  Low: ${report.summary.low}  Info: ${report.summary.info}`)
    if (report.resumo.checksComErro.length > 0) {
      console.log(`  ⚠ Checks com erro: ${report.resumo.checksComErro.join(', ')}`)
    }
    if (report.resumo.checksPulados.length > 0) {
      console.log(`  ⊘ Checks pulados: ${report.resumo.checksPulados.join(', ')}`)
    }
    console.log(`  Duration: ${report.durationMs}ms  Run ID: ${report.runId}`)
  }
}

/** Default de camada/status para findings que o agente não preencheu. */
function normalizeFinding(f: Finding, camada: AgentCategory): Finding {
  return {
    ...f,
    camada: f.camada ?? camada,
    status: f.status ?? 'open',
  }
}

/** Rejeita com erro de timeout se a promise não resolver dentro de `ms`. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout após ${ms}ms`)), ms)
    promise.then(
      value => { clearTimeout(timer); resolve(value) },
      err => { clearTimeout(timer); reject(err) },
    )
  })
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size))
  }
  return chunks
}
