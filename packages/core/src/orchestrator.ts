import { randomUUID } from 'crypto'
import type {
  Target, SecurityAgent, ScanReport, ScanScope, Finding, Severity, ScanDepth
} from './types.js'

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

export interface OrchestratorOptions {
  concurrency?: number
  failOn?: Severity[]
  depth?: ScanDepth
  verbose?: boolean
}

export class FractaOrchestrator {
  private agents: SecurityAgent[] = []
  private readonly options: Required<OrchestratorOptions>

  constructor(options: OrchestratorOptions = {}) {
    this.options = {
      concurrency: options.concurrency ?? 3,
      failOn: options.failOn ?? ['critical', 'high'],
      depth: options.depth ?? 'full',
      verbose: options.verbose ?? false,
    }
  }

  registerAgent(agent: SecurityAgent): this {
    this.agents.push(agent)
    return this
  }

  registerAgents(agents: SecurityAgent[]): this {
    agents.forEach(a => this.registerAgent(a))
    return this
  }

  async scan(target: Target): Promise<ScanReport> {
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

    const findings: Finding[] = []
    const chunks = chunkArray(activeAgents, this.options.concurrency)

    for (const chunk of chunks) {
      const results = await Promise.allSettled(chunk.map(a => a.run(scope)))
      for (const result of results) {
        if (result.status === 'fulfilled') {
          findings.push(...result.value)
        } else {
          console.error(`[Fracta] Agent error:`, result.reason)
        }
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

    const report: ScanReport = {
      runId,
      target: target.name,
      startedAt,
      finishedAt,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      summary,
      findings,
      passed,
    }

    this.printSummary(report)
    return report
  }

  async scanAll(targets: Target[]): Promise<ScanReport[]> {
    const reports: ScanReport[] = []
    for (const target of targets) {
      reports.push(await this.scan(target))
    }
    return reports
  }

  private printSummary(report: ScanReport): void {
    const status = report.passed ? '✅ PASSED' : '❌ FAILED'
    console.log(`\n[Fracta] ${report.target} — ${status}`)
    console.log(`  Critical: ${report.summary.critical}  High: ${report.summary.high}  Medium: ${report.summary.medium}  Low: ${report.summary.low}  Info: ${report.summary.info}`)
    console.log(`  Duration: ${report.durationMs}ms  Run ID: ${report.runId}`)
  }
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size))
  }
  return chunks
}
