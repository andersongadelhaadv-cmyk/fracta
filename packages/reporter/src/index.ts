import { mkdir, writeFile } from 'fs/promises'
import { join } from 'path'
import type { ScanReport, Finding, Severity } from '@fracta/core'

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

  async save(report: ScanReport): Promise<{ mdPath: string; jsonPath: string }> {
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

  private buildMarkdown(report: ScanReport): string {
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
        if (f.references && f.references.length > 0) {
          md += `**Referências:** ${f.references.map(r => `[${r}](${r})`).join(' · ')}\n\n`
        }
        md += `---\n\n`
      }
    }

    md += `*Gerado pelo [Fracta](https://github.com/fracta/fracta) — The Complete SaaS Audit Framework*\n`
    return md
  }
}
