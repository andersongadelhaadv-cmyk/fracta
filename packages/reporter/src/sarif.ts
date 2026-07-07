import type { ScanReport, AuditReport, Finding, Severity } from '@fracta/core'

/**
 * SARIF 2.1.0 — o formato que o GitHub Code Scanning ingere. Transforma o
 * Fracta de "relatório" em CONTROL de CI: os achados aparecem inline no diff da
 * PR, e o `fractaFindingId` (id estável) é o fingerprint que o GitHub usa para
 * rastrear/dedup/suprimir o MESMO achado entre runs — o diff por-finding.
 */
export interface Sarif {
  $schema: string
  version: '2.1.0'
  runs: Array<{
    tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } }
    results: SarifResult[]
  }>
}
interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  defaultConfiguration: { level: SarifLevel }
}
interface SarifResult {
  ruleId: string
  level: SarifLevel
  message: { text: string }
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>
  partialFingerprints: { fractaFindingId: string }
}
type SarifLevel = 'error' | 'warning' | 'note'

const LEVEL: Record<Severity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
}

/** ruleId estável agrupando por categoria+agente (o Finding não tem campo de regra dedicado). */
function ruleIdFor(f: Finding): string {
  return `${f.category}/${slug(f.agent)}`
}

export function toSarif(report: ScanReport | AuditReport, opts: { toolVersion?: string } = {}): Sarif {
  const findings = report.findings ?? []

  const rules = new Map<string, SarifRule>()
  const results: SarifResult[] = findings.map((f) => {
    const id = ruleIdFor(f)
    if (!rules.has(id)) {
      rules.set(id, {
        id,
        name: `${f.agent} (${f.category})`,
        shortDescription: { text: `Achados de ${f.agent}` },
        defaultConfiguration: { level: LEVEL[f.severity] },
      })
    }
    const uri = f.endpoint?.trim() || report.target
    return {
      ruleId: id,
      level: LEVEL[f.severity],
      message: { text: f.description ? `${f.title} — ${f.description}` : f.title },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
      partialFingerprints: { fractaFindingId: f.id },
    }
  })

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Fracta',
            version: opts.toolVersion ?? '0.0.0',
            informationUri: 'https://fracta.pro',
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  }
}
