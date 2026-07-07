import type { Finding } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

/** Um `<script>` observado no DOM + os atributos que decidem cobertura sob CSP. */
export interface ScriptTag {
  inline: boolean
  src?: string
  hasNonce: boolean
  hasIntegrity: boolean
}

/** Um `SecurityPolicyViolationEvent` capturado em runtime (fonte da verdade). */
export interface CspViolation {
  violatedDirective: string
  blockedURI: string
  /** 'enforce' = bloqueado de fato; 'report' = só reportado (Report-Only). */
  disposition: 'enforce' | 'report'
}

export interface CspCoverageInput {
  saas: string
  runId: string
  /** Header Content-Security-Policy (enforce) do documento principal. */
  cspHeader?: string
  /** Header Content-Security-Policy-Report-Only, se houver. */
  cspReportOnlyHeader?: string
  scripts: ScriptTag[]
  violations: CspViolation[]
}

const REFS = [
  'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/script-src',
  'https://owasp.org/www-project-secure-headers/#content-security-policy',
]
const AGENT = 'CSP-coverage (browser)'

/** Diretiva efetiva de script: script-src-elem > script-src > default-src. */
function scriptDirectiveTokens(header: string | undefined): string[] | undefined {
  if (!header) return undefined
  const map = new Map<string, string[]>()
  for (const part of header.split(';')) {
    const [name, ...tokens] = part.trim().split(/\s+/)
    if (name) map.set(name.toLowerCase(), tokens)
  }
  return map.get('script-src-elem') ?? map.get('script-src') ?? map.get('default-src')
}

function isScriptViolation(directive: string): boolean {
  return /^script-src/i.test(directive.trim())
}

/**
 * Traduz a observação de runtime (DOM + violações reais do browser) em achados
 * sobre a COBERTURA da CSP — não a mera presença do header. Prova, não afirma:
 *  - violação em enforce   → medium VERIFIED (scripts bloqueados de fato; o caso 37/38)
 *  - violação em report    → low VERIFIED    (bloquearia se você virasse enforce)
 *  - estrita + 0 violações → info            (prova positiva: cobre 100% dos N scripts)
 *  - 'unsafe-inline'       → info            (a política não restringe scripts; calibrado baixo)
 *  - sem política de script→ [] (defer ao HEADERS agent — não duplica)
 *
 * Baixo falso-positivo por construção: o sinal forte é o evento de violação do
 * próprio browser, não uma heurística sobre a string do header.
 */
export function analyzeCspCoverage(input: CspCoverageInput): Finding[] {
  const { saas, runId, cspHeader, cspReportOnlyHeader, scripts, violations } = input

  const enforceTokens = scriptDirectiveTokens(cspHeader)
  const reportTokens = scriptDirectiveTokens(cspReportOnlyHeader)
  const hasScriptPolicy = !!enforceTokens || !!reportTokens
  if (!hasScriptPolicy) return [] // sem script-src/default-src → problema do HEADERS agent

  const total = scripts.length
  const scriptViolations = violations.filter(v => isScriptViolation(v.violatedDirective))
  const enforceViol = scriptViolations.filter(v => v.disposition === 'enforce')
  const reportViol = scriptViolations.filter(v => v.disposition === 'report')
  const sample = (vs: CspViolation[]) =>
    [...new Set(vs.map(v => v.blockedURI || 'inline'))].slice(0, 6).join(', ')

  const finding = (f: Partial<Finding> & Pick<Finding, 'severity' | 'title' | 'description' | 'recommendation'>): Finding => ({
    id: stableFindingId({ saas, camada: 'security', rule: `csp-coverage.${f.title!.slice(0, 24)}` }),
    runId,
    agent: AGENT,
    category: 'security',
    camada: 'security',
    confidence: 'high',
    references: REFS,
    createdAt: new Date(),
    ...f,
  })

  // 1) Bloqueio REAL em enforce — o gap que "policy ok" jamais pegaria.
  if (enforceViol.length) {
    return [finding({
      severity: 'medium',
      title: 'Scripts bloqueados pela CSP em runtime (cobertura incompleta)',
      description:
        `Verificado em browser real: ${enforceViol.length} de ${total} script(s) foram BLOQUEADOS pela CSP em modo enforce — ` +
        `a política é estrita, mas nem todo <script> está coberto por nonce/hash/allowlist. ` +
        `Isso quebra funcionalidade e costuma levar o time a afrouxar a CSP (ex.: 'unsafe-inline'), regredindo a postura. ` +
        `O header parecia correto; a realidade em runtime não estava.`,
      evidence: `bloqueados (amostra): ${sample(enforceViol)}\ndiretivas: ${[...new Set(enforceViol.map(v => v.violatedDirective))].join(', ')}`,
      recommendation:
        'Cubra TODO <script>: injete o nonce do response em cada tag inline (ou use hash), e allowliste os hosts externos. Confirme 0 violações em runtime antes de considerar a CSP completa.',
    })]
  }

  // 2) Report-Only bloquearia — auditoria pré-enforce.
  if (reportViol.length) {
    return [finding({
      severity: 'low',
      title: 'CSP Report-Only bloquearia scripts se virasse enforce',
      description:
        `Sua CSP está em Report-Only e ${reportViol.length} de ${total} script(s) SERIAM bloqueados se você a colocasse em enforce. ` +
        `Feche a cobertura antes de flipar para enforce, senão a página quebra.`,
      evidence: `seriam bloqueados (amostra): ${sample(reportViol)}`,
      recommendation: 'Cubra os scripts reportados (nonce/hash/allowlist) e só então promova a CSP de Report-Only para enforce.',
    })]
  }

  // 3) 'unsafe-inline' presente → a política não restringe scripts (calibrado baixo).
  if ((enforceTokens ?? reportTokens ?? []).some(t => t.replace(/['"]/g, '').toLowerCase() === 'unsafe-inline')) {
    return [finding({
      severity: 'info',
      confidence: 'high',
      title: "script-src permite 'unsafe-inline' — não restringe scripts",
      description:
        `A CSP tem 'unsafe-inline' em script-src, então qualquer <script> inline é permitido: a cobertura de CSP não é significativa como defesa contra XSS. ` +
        `Não é um bloqueio (por isso info), mas remover 'unsafe-inline' e adotar nonce/hash é o que torna a CSP uma proteção real.`,
      recommendation: "Remova 'unsafe-inline' de script-src e passe a cobrir os scripts com nonce ou hash.",
    })]
  }

  // 4) Estrita, sem 'unsafe-inline', 0 violações → prova POSITIVA de cobertura.
  return [finding({
    severity: 'info',
    confidence: 'high',
    title: `CSP cobre 100% dos ${total} script(s) (verificado em runtime)`,
    description:
      `Carreguei a página num browser real: a CSP é estrita (sem 'unsafe-inline') e NENHUM dos ${total} <script> foi bloqueado. ` +
      `Cobertura confirmada em runtime — não é só o header estar "bonito".`,
    recommendation: 'Mantenha a cobertura: todo novo <script> precisa de nonce/hash ou host allowlistado.',
  })]
}
