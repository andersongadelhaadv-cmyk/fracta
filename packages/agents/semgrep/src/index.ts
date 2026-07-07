import type { SecurityAgent, ScanScope, Finding, AgentCategory, Severity, Confidence } from '@fracta/core'
import { SkippedCheck, stableFindingId, runCommand } from '@fracta/core'

/** Subconjunto do resultado do `semgrep --json` que consumimos. */
export interface SemgrepRawResult {
  check_id: string
  path: string
  start: { line: number }
  extra: {
    message?: string
    severity?: 'ERROR' | 'WARNING' | 'INFO' | string
    metadata?: {
      cwe?: string[]
      owasp?: string[]
      confidence?: string
      references?: string[]
    }
    lines?: string
  }
}

export type SemgrepOutcome =
  | { kind: 'skip'; reason: string }
  | { kind: 'error'; reason: string }
  | { kind: 'findings'; results: SemgrepRawResult[] }

export type SemgrepScanner = (repoPath: string, timeoutMs: number) => Promise<SemgrepRawResult[]>

/** Assinaturas de "binário não encontrado" (pt-BR/en, Windows/POSIX) — igual ao gitleaks. */
function looksLikeMissingBinary(stderr: string): boolean {
  return /reconhecido|recognized|command not found|no such file|cannot find|n[ãa]o encontrad|not found/i.test(stderr)
}

/**
 * Decisão PURA sobre a saída do semgrep (testável sem o binário). Regra do #8:
 * binário ausente → skip honesto (nunca "limpo"); saída ininteligível com erro →
 * error visível; JSON válido → findings (mesmo vazio = limpo de verdade).
 */
export function interpretSemgrep(input: { code: number | null; stdout: string; stderr: string }): SemgrepOutcome {
  const { code, stdout, stderr } = input
  if (looksLikeMissingBinary(stderr) && !stdout.trim()) {
    return { kind: 'skip', reason: 'semgrep não encontrado no PATH — SAST semântico não executado (instale: `pipx install semgrep`)' }
  }
  const trimmed = stdout.trim()
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed) as { results?: SemgrepRawResult[] }
      if (Array.isArray(parsed.results)) return { kind: 'findings', results: parsed.results }
    } catch { /* cai no tratamento de erro abaixo */ }
  }
  // Sem JSON parseável: code 0 = limpo; qualquer outro = anomalia visível (nunca falso-verde).
  if (code === 0) return { kind: 'findings', results: [] }
  return { kind: 'error', reason: `semgrep terminou com code ${code} e saída não-parseável: ${(stderr || stdout).slice(0, 200)}` }
}

const SEV: Record<string, Severity> = { ERROR: 'high', WARNING: 'medium', INFO: 'low' }
const CONF: Record<string, Confidence> = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }

/** Traduz resultados do semgrep em Findings do Fracta — pura/testável. */
export function mapSemgrepFindings(input: { saas: string; runId: string; results: SemgrepRawResult[] }): Finding[] {
  const { saas, runId, results } = input
  return results.map((r) => {
    const severity = SEV[String(r.extra.severity).toUpperCase()] ?? 'medium'
    // Confiança: do metadata do semgrep; default `medium` (semgrep pode gerar FP → não afirma `high` à toa).
    const confidence = CONF[String(r.extra.metadata?.confidence ?? '').toUpperCase()] ?? 'medium'
    const cwe = r.extra.metadata?.cwe ?? []
    const owasp = r.extra.metadata?.owasp ?? []
    const refs = [...cwe, ...owasp, ...(r.extra.metadata?.references ?? [])]
    const shortRule = r.check_id.split('.').slice(-2).join('.') || r.check_id
    return {
      id: stableFindingId({ saas, camada: 'code', rule: `semgrep:${r.check_id}`, location: `${r.path}:${r.start.line}` }),
      runId,
      agent: 'SEMGREP Agent',
      category: 'code' as AgentCategory,
      camada: 'code' as AgentCategory,
      severity,
      confidence,
      title: `SAST (semgrep): ${shortRule} — ${r.path}:${r.start.line}`,
      description: `${r.extra.message ?? r.check_id} (regra: ${r.check_id}). Análise semântica/dataflow — não é só regex.`,
      location: { file: r.path, line: r.start.line },
      evidence: r.extra.lines ? `${r.path}:${r.start.line} — ${r.extra.lines.trim().slice(0, 200)}` : `${r.path}:${r.start.line}`,
      recommendation: r.extra.message ?? 'Reveja o trecho sinalizado pelo semgrep e aplique a correção da regra.',
      references: refs.length ? refs : ['https://semgrep.dev/'],
      createdAt: new Date(),
    }
  })
}

/** Ruleset default: pack de segurança do semgrep. Configurável via FRACTA_SEMGREP_CONFIG. */
const DEFAULT_CONFIG = process.env.FRACTA_SEMGREP_CONFIG ?? 'p/security-audit'

/**
 * Classifica um erro de execução do semgrep num MOTIVO de skip honesto (ou `null`
 * = re-lançar como erro real). Pura/testável. Cobre: binário ausente (ENOENT) e
 * timeout (o semgrep no Windows cai no pysemgrep lento e pendura) — ambos viram
 * `skipped`, nunca derrubam o scan.
 */
export function semgrepSkipReasonFor(err: unknown): string | null {
  const e = err as NodeJS.ErrnoException
  if (e?.code === 'ENOENT') {
    return 'semgrep não encontrado no PATH — SAST semântico não executado (instale: `pipx install semgrep`)'
  }
  if (/timeout/i.test(e?.message ?? '')) {
    return 'semgrep excedeu o tempo — SAST semântico não concluído (é lento no Windows; rode em CI/Linux ou ajuste FRACTA_SEMGREP_TIMEOUT)'
  }
  return null
}

export const defaultSemgrepScan: SemgrepScanner = async (repoPath, timeoutMs) => {
  let code: number | null
  let stdout = ''
  let stderr = ''
  try {
    const result = await runCommand(
      'semgrep',
      [
        'scan', '--config', DEFAULT_CONFIG, '--json', '--quiet',
        // Respeita .gitignore (pula node_modules/dist) — SEM isto varreria tudo.
        // Auto-bounds do próprio semgrep para não pendurar: timeout por-regra/arquivo,
        // desiste do arquivo após 3 regras estourarem, sem telemetria de rede.
        '--timeout', '15', '--timeout-threshold', '3', '--metrics=off',
        repoPath,
      ],
      { timeoutMs },
    )
    code = result.code
    stdout = result.stdout
    stderr = result.stderr
  } catch (err) {
    // ENOENT (ausente) e timeout (semgrep lento no Windows) → SKIP honesto, NUNCA
    // trava/erra o scan inteiro. Em CI/Linux o core rápido roda em segundos.
    const reason = semgrepSkipReasonFor(err)
    if (reason) throw new SkippedCheck(reason)
    throw err
  }
  const outcome = interpretSemgrep({ code, stdout, stderr })
  if (outcome.kind === 'skip') throw new SkippedCheck(outcome.reason)
  if (outcome.kind === 'error') throw new Error(outcome.reason)
  return outcome.results
}

/**
 * SAST SEMÂNTICO via semgrep (dataflow/taint) — o salto de "linter regex" para
 * "engine". Complementa os agentes determinísticos com recall de injeção/broken-access
 * que padrão de string não pega. Read-only; `skipped` honesto quando o binário está
 * ausente (Windows/npx) — ausência ≠ seguro. Correções são só PROPOSTAS.
 */
export class SemgrepAgent implements SecurityAgent {
  name = 'SEMGREP Agent'
  category: AgentCategory = 'code'
  concurrency = 1
  // Timeout total (s) configurável — default 120s. Backstop do runCommand: se o
  // semgrep pendurar (Windows), o scan degrada para `skipped`, não trava.
  timeoutMs = Math.max(10, Number(process.env.FRACTA_SEMGREP_TIMEOUT ?? 120)) * 1000

  constructor(private readonly scan: SemgrepScanner = defaultSemgrepScan) {}

  async run(scope: ScanScope): Promise<Finding[]> {
    const repoPath = scope.target.repoPath
    if (!repoPath) {
      throw new SkippedCheck('sem repoPath — SEMGREP Agent precisa do repositório local')
    }
    const results = await this.scan(repoPath, this.timeoutMs)
    return mapSemgrepFindings({ saas: scope.target.name, runId: scope.runId, results })
  }
}
