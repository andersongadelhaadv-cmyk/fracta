import { mkdir, writeFile } from 'fs/promises'
import { join } from 'path'
import type { ScanReport, AuditReport, Finding, Severity } from '@fracta/core'

/** Type guard: relatório enriquecido (Fase 1+) traz `checks`/`resumo`. */
function isAuditReport(r: ScanReport | AuditReport): r is AuditReport {
  return Array.isArray((r as AuditReport).checks)
}

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
}

export interface ReporterOptions {
  outputDir?: string
}

export class FractaReporter {
  private readonly outputDir: string

  constructor(options: ReporterOptions = {}) {
    this.outputDir = options.outputDir ?? './fracta-reports'
  }

  async save(report: ScanReport | AuditReport): Promise<{ mdPath: string; jsonPath: string }> {
    await mkdir(this.outputDir, { recursive: true })

    const slug = report.target.toLowerCase().replace(/[^a-z0-9]+/g, '-')
    const ts = new Date(report.startedAt)
      .toISOString()
      .replace(/[:.]/g, '-')
      .replace('T', '_')
      .substring(0, 19)

    const baseName = `${slug}-${ts}`
    const mdPath = join(this.outputDir, `${baseName}.md`)
    const jsonPath = join(this.outputDir, `${baseName}.json`)

    await writeFile(mdPath, this.buildMarkdown(report), 'utf-8')
    await writeFile(jsonPath, JSON.stringify(report, null, 2), 'utf-8')

    return { mdPath, jsonPath }
  }

  private buildMarkdown(report: ScanReport | AuditReport): string {
    const date = new Date(report.startedAt)
    const dateStr = date.toLocaleDateString('pt-BR') + ' ' + date.toLocaleTimeString('pt-BR')
    const durationSec = (report.durationMs / 1000).toFixed(1)
    const status = report.passed ? '✅ PASSOU' : '❌ FALHOU'

    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
    const grouped = new Map<Severity, Finding[]>()
    for (const s of severities) grouped.set(s, [])
    for (const f of report.findings) grouped.get(f.severity)!.push(f)

    let md = `# 🛡️ Fracta — Relatório de Segurança\n\n`

    md += `| Campo | Valor |\n|---|---|\n`
    md += `| Target | ${report.target} |\n`
    md += `| Data | ${dateStr} |\n`
    md += `| Duração | ${durationSec}s |\n`
    md += `| Run ID | \`${report.runId}\` |\n`
    md += `| Status | ${status} |\n\n`

    md += `## 📊 Resumo\n\n`
    md += `| Severidade | Quantidade |\n|---|---|\n`
    md += `| 🔴 Critical | ${report.summary.critical} |\n`
    md += `| 🟠 High | ${report.summary.high} |\n`
    md += `| 🟡 Medium | ${report.summary.medium} |\n`
    md += `| 🔵 Low | ${report.summary.low} |\n`
    md += `| ⚪ Info | ${report.summary.info} |\n`
    md += `| **Total** | **${report.summary.total}** |\n\n`

    // Topo: ação prioritária — ordem do LLM quando houver, senão critical/high.
    md += this.buildPriorityBlock(report)

    const severityTitles: Record<Severity, string> = {
      critical: '🔴 CRÍTICO',
      high: '🟠 ALTO',
      medium: '🟡 MÉDIO',
      low: '🔵 BAIXO',
      info: '⚪ INFORMATIVO',
    }

    for (const severity of severities) {
      const findings = grouped.get(severity)!
      if (findings.length === 0) continue

      md += `## ${severityTitles[severity]} (${findings.length})\n\n`

      for (const f of findings) {
        md += `### ${f.title}\n\n`
        md += `**Agente:** \`${f.agent}\` | **Categoria:** \`${f.category}\`\n`
        if (f.endpoint) md += `**Endpoint:** \`${f.endpoint}\`\n`
        md += `\n${f.description}\n\n`
        if (f.evidence) {
          md += `**Evidência:**\n\`\`\`\n${f.evidence}\n\`\`\`\n\n`
        }
        md += `**Correção:** ${f.recommendation}\n\n`
        md += this.renderProposedFix(f)
        if (f.references && f.references.length > 0) {
          md += `**Referências:** ${f.references.map(r => `[${r}](${r})`).join(' · ')}\n\n`
        }
        md += `---\n\n`
      }
    }

    if (isAuditReport(report)) {
      md += this.buildTransparencySection(report)
    }

    md += `*Gerado pelo [Fracta](https://github.com/fracta/fracta) — The Complete SaaS Audit Framework*\n`
    return md
  }

  /**
   * Bloco de ação prioritária no topo do relatório. Quando a borda LLM produziu
   * uma `prioritization`, respeita exatamente essa ordem ("o que resolver primeiro")
   * e mostra o racional. Sem LLM, cai no determinístico: lista critical + high.
   * Nunca inventa nada — só referencia findings que existem no relatório.
   */
  private buildPriorityBlock(report: ScanReport | AuditReport): string {
    const byId = new Map(report.findings.map(f => [f.id, f]))
    const prioritization = isAuditReport(report) ? report.prioritization : undefined

    // Caminho LLM: ordem explícita de findings ids.
    if (prioritization && prioritization.order.length > 0) {
      const ordered = prioritization.order
        .map(id => byId.get(id))
        .filter((f): f is Finding => f !== undefined)

      if (ordered.length > 0) {
        let md = `## 🎯 Ação Prioritária\n\n`
        md += `> Ordem sugerida pela borda LLM (prioriza por contexto do SaaS; **não** altera severidade nem o conjunto de achados).\n\n`
        ordered.forEach((f, i) => {
          md += `${i + 1}. ${SEVERITY_EMOJI[f.severity]} **${f.title}** — \`${f.agent}\`\n`
        })
        if (prioritization.rationale) {
          md += `\n> ${prioritization.rationale.trim().replace(/\n+/g, '\n> ')}\n`
        }
        md += `\n`
        return md
      }
    }

    // Caminho determinístico: destaca critical + high no topo.
    const topo = report.findings.filter(f => f.severity === 'critical' || f.severity === 'high')
    if (topo.length === 0) return ''

    let md = `## 🎯 Ação Prioritária (${topo.length})\n\n`
    md += `> Achados de severidade **crítica/alta** — tratar primeiro.\n\n`
    for (const f of topo) {
      md += `- ${SEVERITY_EMOJI[f.severity]} **${f.title}** — \`${f.agent}\`\n`
    }
    md += `\n`
    return md
  }

  /**
   * Renderiza a correção PROPOSTA (gated) de um finding, se houver. Mostra
   * descrição, comando e/ou diff e — sempre — o risco de aplicar. Deixa explícito
   * que o Fracta NUNCA aplica a correção sozinho (regra 2/6).
   */
  private renderProposedFix(f: Finding): string {
    const fix = f.proposedFix
    if (!fix) return ''

    let md = `**🔧 Correção proposta (gated — não aplicada automaticamente):**\n\n`
    md += `${fix.description}\n\n`
    if (fix.command) {
      md += `\`\`\`bash\n${fix.command}\n\`\`\`\n\n`
    }
    if (fix.diff) {
      md += `\`\`\`diff\n${fix.diff}\n\`\`\`\n\n`
    }
    md += `**Risco de aplicar:** ${fix.riskOfApplying}\n\n`
    return md
  }

  /**
   * Transparência sobre o que NÃO foi verificado. Parte da robustez:
   * "não verificado" ≠ "seguro". Lista checks com erro e checks pulados.
   */
  private buildTransparencySection(report: AuditReport): string {
    const { resumo } = report
    let md = ''

    if (resumo.regressoes > 0) {
      md += `## ⏪ Regressões (${resumo.regressoes})\n\n`
      const regs = report.findings.filter(f => f.status === 'regression')
      for (const f of regs) {
        md += `- **${f.title}** (\`${f.agent}\`, ${f.severity}) — voltou a aparecer.\n`
      }
      md += `\n`
    }

    if (resumo.checksComErro.length > 0 || resumo.checksPulados.length > 0) {
      md += `## ⚠️ Checks que NÃO rodaram\n\n`
      md += `> Estes checks não produziram veredito. Ausência de achado aqui **não** significa "seguro".\n\n`

      const byAgent = new Map(report.checks.map(c => [c.agent, c]))

      if (resumo.checksComErro.length > 0) {
        md += `**Erro (falha isolada):**\n\n`
        for (const agent of resumo.checksComErro) {
          md += `- \`${agent}\` — ${byAgent.get(agent)?.motivo ?? 'erro não especificado'}\n`
        }
        md += `\n`
      }

      if (resumo.checksPulados.length > 0) {
        md += `**Pulados (sem dados de entrada):**\n\n`
        for (const agent of resumo.checksPulados) {
          md += `- \`${agent}\` — ${byAgent.get(agent)?.motivo ?? 'sem motivo registrado'}\n`
        }
        md += `\n`
      }
    }

    return md
  }
}
