import { randomUUID } from 'crypto'
import {
  SkippedCheck,
} from './types.js'
import type {
  Target, SecurityAgent, AuditReport, ScanScope, Finding, Severity,
  ScanDepth, CheckResult, AgentCategory, TargetHealth, FindingStore,
} from './types.js'

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

export interface OrchestratorOptions {
  concurrency?: number
  failOn?: Severity[]
  depth?: ScanDepth
  verbose?: boolean
  /** Persistência opcional para regressão/supressão (injetada pelo cli/mcp). */
  store?: FindingStore
}

export class FractaOrchestrator {
  private agents: SecurityAgent[] = []
  private readonly options: Required<Omit<OrchestratorOptions, 'store'>>
  private readonly store?: FindingStore

  constructor(options: OrchestratorOptions = {}) {
    this.options = {
      concurrency: options.concurrency ?? 3,
      failOn: options.failOn ?? ['critical', 'high'],
      depth: options.depth ?? 'full',
      verbose: options.verbose ?? false,
    }
    this.store = options.store
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

    const scope: ScanScope = {
      target,
      depth: this.options.depth,
      agents: activeAgents.map(a => a.name),
      runId,
      startedAt,
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

    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

    const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      summary.total++
      summary[f.severity]++
    }

    const finishedAt = new Date()
    const passed = !this.options.failOn.some(s => summary[s] > 0)

    // TODO(Fase 3): substituir por TargetHealthCheck real (repo git? staging? vps?).
    const targetHealth: TargetHealth = { repoAccessible: true, status: 'healthy' }

    const report: AuditReport = {
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

  private printSummary(report: AuditReport): void {
    const status = report.passed ? '✅ PASSED' : '❌ FAILED'
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
