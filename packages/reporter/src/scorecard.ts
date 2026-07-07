import type { Finding, Severity } from '@fracta/core'

/** OWASP Top 10 2021 — o framework canônico que clientes conhecem. */
const OWASP_2021: Array<{ id: string; name: string }> = [
  { id: 'A01', name: 'Broken Access Control' },
  { id: 'A02', name: 'Cryptographic Failures' },
  { id: 'A03', name: 'Injection' },
  { id: 'A04', name: 'Insecure Design' },
  { id: 'A05', name: 'Security Misconfiguration' },
  { id: 'A06', name: 'Vulnerable and Outdated Components' },
  { id: 'A07', name: 'Identification and Authentication Failures' },
  { id: 'A08', name: 'Software and Data Integrity Failures' },
  { id: 'A09', name: 'Security Logging and Monitoring Failures' },
  { id: 'A10', name: 'Server-Side Request Forgery' },
]

/** CWE → OWASP 2021 (curado para os CWEs que o Fracta de fato emite). */
const CWE_TO_OWASP: Record<string, string> = {
  '639': 'A01', '285': 'A01', '200': 'A01', '352': 'A01', '862': 'A01',
  '347': 'A02', '311': 'A02', '319': 'A02',
  '79': 'A03', '89': 'A03', '94': 'A03', '78': 'A03', '77': 'A03',
  '362': 'A04',
  '16': 'A05', '693': 'A05', '942': 'A05',
  '208': 'A07', '287': 'A07', '307': 'A07', '798': 'A07',
  '918': 'A10',
}

/** OWASP API Security 2023 (códigos 0xaN nas URLs) → Top 10 2021. */
const APICAT_TO_OWASP: Record<string, string> = {
  '0xa1': 'A01', '0xa3': 'A01', '0xa5': 'A01',
  '0xa2': 'A07',
}

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

/**
 * Classifica UM finding numa categoria OWASP 2021 (ou LGPD/unclassified) por
 * SINAIS EXPLÍCITOS — token A0X:2021, CWE mapeado, código OWASP-API, ou categoria
 * de agente de alta confiança (deps→A06, compliance→LGPD). Nunca chuta: sem sinal
 * confiável → 'unclassified' (honestidade > cobertura fake).
 */
export function classifyOwasp(finding: Finding): string {
  const hay = [finding.title, finding.description, ...(finding.references ?? [])].join(' ')

  const explicit = hay.match(/\bA(\d{2}):2021\b/i)
  if (explicit) return `A${explicit[1]}`

  const cwe = hay.match(/(?:CWE-|definitions\/)(\d+)/i)
  if (cwe && CWE_TO_OWASP[cwe[1]]) return CWE_TO_OWASP[cwe[1]]

  const api = hay.match(/0xa[0-9]/i)
  if (api && APICAT_TO_OWASP[api[0].toLowerCase()]) return APICAT_TO_OWASP[api[0].toLowerCase()]

  if (finding.category === 'deps') return 'A06'
  if (finding.category === 'compliance') return 'LGPD'

  return 'unclassified'
}

export interface ScorecardRow {
  id: string
  name: string
  count: number
  maxSeverity: Severity | 'none'
}

const EXTRA_NAMES: Record<string, string> = {
  LGPD: 'Privacidade / LGPD (fora do OWASP Top 10)',
  unclassified: 'Não classificado',
}

/**
 * Rollup dos findings por categoria OWASP 2021 → um scorecard de postura ("limpo
 * em 7, exposto em 3"). Mostra SEMPRE as 10 categorias (cobertura visível, mesmo
 * as limpas); LGPD e "não classificado" só aparecem quando têm achados.
 */
export function buildScorecard(findings: Finding[]): ScorecardRow[] {
  const acc = new Map<string, { count: number; rank: number }>()
  for (const cat of OWASP_2021) acc.set(cat.id, { count: 0, rank: -1 })

  for (const f of findings) {
    const id = classifyOwasp(f)
    const cur = acc.get(id) ?? { count: 0, rank: -1 }
    cur.count += 1
    cur.rank = Math.max(cur.rank, SEV_RANK[f.severity])
    acc.set(id, cur)
  }

  const rankToSev = (r: number): Severity | 'none' =>
    r < 0 ? 'none' : (['info', 'low', 'medium', 'high', 'critical'][r] as Severity)

  const rows: ScorecardRow[] = OWASP_2021.map(cat => {
    const a = acc.get(cat.id)!
    return { id: cat.id, name: cat.name, count: a.count, maxSeverity: rankToSev(a.rank) }
  })

  for (const id of ['LGPD', 'unclassified']) {
    const a = acc.get(id)
    if (a && a.count > 0) rows.push({ id, name: EXTRA_NAMES[id], count: a.count, maxSeverity: rankToSev(a.rank) })
  }

  return rows
}
