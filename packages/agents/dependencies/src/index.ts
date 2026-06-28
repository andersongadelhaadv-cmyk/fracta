import { join } from 'node:path'
import { stat } from 'node:fs/promises'
import type {
  SecurityAgent, ScanScope, Finding, AgentCategory, Severity, ProposedFix,
  CommandResult, CommandRunner,
} from '@fracta/core'
import { SkippedCheck, stableFindingId, runCommand } from '@fracta/core'

// npm severity → severidade do Fracta. A severidade vem da ferramenta, nunca do LLM.
const SEVERITY_MAP: Record<string, Severity> = {
  info: 'info', low: 'low', moderate: 'medium', high: 'high', critical: 'critical',
}

interface NpmAuditFix {
  name: string
  version: string
  isSemVerMajor: boolean
}

interface NpmAuditVuln {
  name: string
  severity: string
  range?: string
  via?: Array<string | { title?: string; url?: string; severity?: string }>
  fixAvailable?: boolean | NpmAuditFix
}

interface NpmAuditReport {
  vulnerabilities?: Record<string, NpmAuditVuln>
  metadata?: unknown
}

/**
 * Detecta dependências vulneráveis via `npm audit --json` (read-only).
 * A detecção é determinística — a severidade vem da própria ferramenta.
 * `skipped` (nunca falso "seguro") quando falta repoPath, package.json, lockfile ou npm.
 * Correções são apenas PROPOSTAS (proposedFix com riskOfApplying), nunca aplicadas.
 */
export class DependenciesAgent implements SecurityAgent {
  name = 'DEPENDENCIES Agent'
  category: AgentCategory = 'deps'
  concurrency = 1
  timeoutMs = 120_000

  constructor(private readonly runner: CommandRunner = runCommand) {}

  async run(scope: ScanScope): Promise<Finding[]> {
    const repoPath = scope.target.repoPath
    if (!repoPath) {
      throw new SkippedCheck('sem repoPath — DependenciesAgent precisa do repositório local')
    }
    await this.ensurePackageJson(repoPath)

    let result: CommandResult
    try {
      result = await this.runner('npm', ['audit', '--json'], { cwd: repoPath, timeoutMs: this.timeoutMs })
    } catch (err) {
      const e = err as NodeJS.ErrnoException
      if (e.code === 'ENOENT') {
        throw new SkippedCheck('npm não encontrado no PATH — não foi possível auditar dependências')
      }
      throw err // erro real de execução → status: error (visível, não falso "seguro")
    }

    const audit = this.parse(result.stdout)
    if (!audit) {
      const needsLock = /lockfile|package-lock|shrinkwrap|requires/i.test(result.stderr)
      throw new SkippedCheck(
        needsLock
          ? 'sem package-lock.json/npm-shrinkwrap — npm audit não pôde rodar de forma confiável'
          : `saída de npm audit não pôde ser interpretada: ${result.stderr.slice(0, 200) || 'vazia'}`,
      )
    }

    return this.toFindings(scope, audit)
  }

  private async ensurePackageJson(repoPath: string): Promise<void> {
    try {
      await stat(join(repoPath, 'package.json'))
    } catch {
      throw new SkippedCheck(`sem package.json em ${repoPath} — não parece um projeto Node`)
    }
  }

  private parse(stdout: string): NpmAuditReport | null {
    try {
      const parsed = JSON.parse(stdout) as NpmAuditReport
      if (parsed && typeof parsed === 'object' && ('vulnerabilities' in parsed || 'metadata' in parsed)) {
        return parsed
      }
      return null
    } catch {
      return null
    }
  }

  private toFindings(scope: ScanScope, audit: NpmAuditReport): Finding[] {
    const findings: Finding[] = []
    const vulns = audit.vulnerabilities ?? {}

    for (const [name, vuln] of Object.entries(vulns)) {
      const severity = SEVERITY_MAP[vuln.severity] ?? 'info'
      const via = this.summarizeVia(vuln.via)
      const proposedFix = this.buildFix(name, vuln.fixAvailable)

      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `npm-audit:${name}`, location: name }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity,
        title: `Dependência vulnerável: ${name} (${vuln.severity})`,
        description: `O pacote ${name}${vuln.range ? ` (faixa ${vuln.range})` : ''} tem vulnerabilidade ${vuln.severity} reportada por npm audit.${via ? ` Via: ${via}.` : ''}`,
        evidence: `npm audit → ${name}: severity=${vuln.severity}${vuln.range ? `, range=${vuln.range}` : ''}`,
        recommendation: proposedFix.description,
        proposedFix,
        createdAt: new Date(),
      })
    }

    return findings
  }

  private summarizeVia(via: NpmAuditVuln['via']): string {
    if (!Array.isArray(via) || via.length === 0) return ''
    return via
      .map(v => (typeof v === 'string' ? v : v.title ?? v.url ?? ''))
      .filter(Boolean)
      .join('; ')
  }

  private buildFix(name: string, fix: NpmAuditVuln['fixAvailable']): ProposedFix {
    if (fix === true) {
      return {
        description: `Rode \`npm audit fix\` para corrigir ${name} com updates compatíveis.`,
        command: 'npm audit fix',
        riskOfApplying: 'npm audit fix aplica apenas updates semver-compatíveis; rode a suíte de testes depois. Risco baixo, mas não nulo.',
      }
    }
    if (fix && typeof fix === 'object') {
      const major = fix.isSemVerMajor
      return {
        description: `Atualize ${name} para ${fix.name}@${fix.version}${major ? ' (MUDANÇA DE MAJOR — pode quebrar)' : ''}.`,
        command: `npm install ${fix.name}@${fix.version}`,
        riskOfApplying: major
          ? 'Atualização de major version: pode quebrar a API/comportamento. Leia o changelog e teste antes de aplicar.'
          : 'Atualização menor/patch: baixo risco; ainda assim rode os testes após aplicar.',
      }
    }
    return {
      description: `Sem correção automática para ${name}. Avalie substituir/remover a dependência ou aguardar patch upstream.`,
      riskOfApplying: 'Sem fix disponível: mitigar manualmente. Remover a dependência pode quebrar funcionalidade — valide o uso antes.',
    }
  }
}
