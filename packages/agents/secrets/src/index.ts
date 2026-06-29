import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { mkdtemp, readFile, rm, readdir } from 'node:fs/promises'
import type {
  SecurityAgent, ScanScope, Finding, AgentCategory, ProposedFix,
} from '@fracta/core'
import { SkippedCheck, stableFindingId, runCommand } from '@fracta/core'

/**
 * Subconjunto dos campos de um achado do gitleaks que ESTE agente pode tocar.
 * Os campos `Secret` e `Match` existem no JSON do gitleaks mas NUNCA são usados
 * aqui — incluí-los em qualquer Finding recriaria o vazamento que estamos achando.
 */
export interface GitleaksFinding {
  RuleID?: string
  Description?: string
  File?: string
  StartLine?: number
  Commit?: string
  Date?: string
  Author?: string
  // Secret / Match são deliberadamente OMITIDOS do tipo público — nunca propagados.
}

/**
 * Scanner injetável. A impl real roda o binário `gitleaks`; os testes injetam
 * um fake com dados canned (sem tocar Git/PATH).
 */
export type GitleaksScanner = (repoPath: string, timeoutMs: number) => Promise<GitleaksFinding[]>

/**
 * Decisão sobre o resultado bruto do gitleaks (lógica pura, testável).
 * - `findings` — execução válida (com ou sem vazamentos).
 * - `skip`     — gitleaks ausente: vira `SkippedCheck` honesto (nunca "limpo").
 * - `error`    — anomalia: NUNCA tratada como "limpo" (regra de honestidade).
 */
export type GitleaksOutcome =
  | { kind: 'findings'; findings: GitleaksFinding[] }
  | { kind: 'skip'; reason: string }
  | { kind: 'error'; reason: string }

/**
 * Assinaturas de "binário não encontrado". No Windows com `shell:true`, um
 * binário ausente NÃO emite ENOENT — o shell resolve com code≠0 e um stderr
 * "não é reconhecido"/"not recognized" (pt-BR/en); shells POSIX usam
 * "command not found" + code 127. cmd.exe usa 9009.
 */
function looksLikeMissingBinary(code: number | null, stderr: string): boolean {
  if (code === 127 || code === 9009) return true
  // Tokens robustos a mojibake do codepage do Windows (cmd.exe pt-BR converte
  // "não é reconhecido" em "n�o � reconhecido" — só "reconhecido" sobrevive).
  return /reconhecido|recognized|command not found|no such file|cannot find|n[ãa]o encontrad/i.test(stderr)
}

/**
 * Interpreta o resultado do gitleaks. gitleaks: 0 = limpo, 1 = vazamentos
 * ENCONTRADOS (e SEMPRE grava o relatório). Logo:
 * - code 0: limpo (relatório vazio/ausente é esperado) → findings [].
 * - code 1 + relatório com JSON: vazamentos → findings parseados.
 * - code 1 SEM relatório: contradição (não é "limpo") → error — a menos que o
 *   stderr indique binário ausente, caso em que é `skip` honesto. Era exatamente
 *   aqui que o veredito ✅ PASSOU silencioso nascia (#8).
 * - qualquer outro código: error (nunca "limpo").
 */
export function interpretGitleaks(input: {
  code: number | null
  stderr: string
  report: string | null
}): GitleaksOutcome {
  const { code, stderr, report } = input

  if (looksLikeMissingBinary(code, stderr)) {
    return { kind: 'skip', reason: 'gitleaks não encontrado no PATH — não foi possível escanear segredos versionados' }
  }

  const trimmed = (report ?? '').trim()
  const parseReport = (): GitleaksFinding[] => {
    if (!trimmed) return []
    const parsed = JSON.parse(trimmed) as GitleaksFinding[]
    return Array.isArray(parsed) ? parsed : []
  }

  if (code === 0) return { kind: 'findings', findings: parseReport() }

  if (code === 1) {
    if (!trimmed) {
      return { kind: 'error', reason: 'gitleaks saiu com código 1 (vazamentos) mas não gerou relatório — resultado inconclusivo, não tratado como "limpo"' }
    }
    return { kind: 'findings', findings: parseReport() }
  }

  return { kind: 'error', reason: `gitleaks saiu com código inesperado (${code ?? 'null'})` }
}

/**
 * Impl real: roda `gitleaks detect` gravando o relatório JSON num arquivo temporário,
 * lê+parseia e limpa. A decisão sobre o resultado é delegada a `interpretGitleaks`
 * (pura/testada): binário ausente → SkippedCheck honesto; anomalia → erro visível.
 * NUNCA reporta "limpo" quando o scan não rodou de verdade (#8).
 */
export const defaultGitleaksScan: GitleaksScanner = async (repoPath, timeoutMs) => {
  const dir = await mkdtemp(join(tmpdir(), 'fracta-gitleaks-'))
  const reportPath = join(dir, 'report.json')
  try {
    let code: number | null
    let stderr = ''
    try {
      const result = await runCommand(
        'gitleaks',
        [
          'detect',
          '--source', repoPath,
          '--no-banner',
          '--report-format', 'json',
          '--report-path', reportPath,
        ],
        { timeoutMs },
      )
      code = result.code
      stderr = result.stderr
    } catch (err) {
      const e = err as NodeJS.ErrnoException
      if (e.code === 'ENOENT') {
        throw new SkippedCheck('gitleaks não encontrado no PATH — não foi possível escanear segredos versionados')
      }
      throw err // erro real de execução → status: error (visível, não falso "seguro")
    }

    // Lê o relatório (pode não existir). `null` = ausente — interpretGitleaks decide.
    let report: string | null = null
    try {
      report = await readFile(reportPath, 'utf8')
    } catch {
      report = null
    }

    const outcome = interpretGitleaks({ code, stderr, report })
    if (outcome.kind === 'skip') throw new SkippedCheck(outcome.reason)
    if (outcome.kind === 'error') throw new Error(outcome.reason)
    return outcome.findings
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

/**
 * Detecta SEGREDOS versionados via gitleaks + checagens de higiene (read-only).
 *
 * Garantia de sanitização: os valores de segredo (campos `Secret`/`Match` do gitleaks)
 * NUNCA entram em nenhum Finding — só RuleID, File, StartLine e hash curto do commit.
 * Logar/reportar o segredo recriaria o vazamento.
 *
 * `skipped` (nunca falso "seguro") quando falta repoPath ou o binário gitleaks.
 * Correções são apenas PROPOSTAS (proposedFix com riskOfApplying), nunca aplicadas —
 * o agente nunca toca no Git.
 */
export class SecretsAgent implements SecurityAgent {
  name = 'SECRETS Agent'
  category: AgentCategory = 'secrets'
  concurrency = 1
  timeoutMs = 120_000

  constructor(private readonly scan: GitleaksScanner = defaultGitleaksScan) {}

  async run(scope: ScanScope): Promise<Finding[]> {
    const repoPath = scope.target.repoPath
    if (!repoPath) {
      throw new SkippedCheck('sem repoPath — SecretsAgent precisa do repositório local')
    }

    const findings: Finding[] = []

    const leaks = await this.scan(repoPath, this.timeoutMs)
    for (const leak of leaks) {
      findings.push(this.toLeakFinding(scope, leak))
    }

    findings.push(...await this.hygieneFindings(scope, repoPath))

    return findings
  }

  /** Mapeia um achado do gitleaks → Finding, SEM jamais incluir o valor do segredo. */
  private toLeakFinding(scope: ScanScope, leak: GitleaksFinding): Finding {
    const ruleId = leak.RuleID ?? 'unknown-rule'
    const file = leak.File ?? 'unknown-file'
    const line = leak.StartLine ?? 0
    const commit = leak.Commit ?? ''
    const shortCommit = commit ? commit.slice(0, 8) : 'sem-commit'

    const proposedFix: ProposedFix = {
      description: 'Revogue/rotacione a credencial no provedor (Anthropic/Meta/Resend/etc.). Remover do histórico Git NÃO substitui a rotação.',
      riskOfApplying: 'Rotacionar pode derrubar integrações que usam a chave antiga até atualizar o segredo no ambiente. Reescrever histórico Git é destrutivo e exige force-push coordenado.',
    }

    return {
      id: stableFindingId({
        saas: scope.target.name,
        camada: this.category,
        rule: `gitleaks:${ruleId}:${file}:${line}`,
        location: file,
      }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'critical',
      title: `Segredo versionado: ${ruleId} em ${file}`,
      description: `gitleaks detectou um segredo versionado correspondente à regra ${ruleId} em ${file} (linha ${line}). O valor do segredo é deliberadamente omitido deste relatório para não recriar o vazamento.`,
      evidence: `${file}:${line} (commit ${shortCommit}) — regra ${ruleId}`,
      recommendation: proposedFix.description,
      proposedFix,
      createdAt: new Date(),
    }
  }

  /** Checagens de higiene de configuração de segredos (read-only). */
  private async hygieneFindings(scope: ScanScope, repoPath: string): Promise<Finding[]> {
    const findings: Finding[] = []

    const gitignore = await this.readFileSafe(join(repoPath, '.gitignore'))
    if (gitignore === null) {
      // Pior cenário: sem .gitignore E com arquivo .env presente no repositório.
      const committedEnv = await this.findEnvFiles(repoPath)
      if (committedEnv.length > 0) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'no-gitignore-with-env', location: '.env' }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: 'high',
          title: 'Repositório sem .gitignore com arquivo .env versionado',
          description: `Não existe .gitignore neste repositório e foi encontrado pelo menos um arquivo de ambiente (${committedEnv.join(', ')}) que pode conter credenciais reais versionadas. Sem .gitignore, qualquer .env presente está exposto ao histórico Git.`,
          evidence: `Arquivos .env encontrados sem proteção de .gitignore: ${committedEnv.join(', ')}`,
          recommendation: 'Crie um .gitignore ignorando `.env` e suas variantes. Execute `git rm --cached <arquivo>` para remover arquivos já versionados e rotacione todos os segredos que possam ter sido expostos no histórico.',
          proposedFix: {
            description: 'Crie um .gitignore com a entrada `.env` (e variantes como `.env.*`). Use `git rm --cached .env` para remover do rastreamento e rotacione os segredos expostos no provedor.',
            riskOfApplying: 'Médio. Criar o .gitignore é seguro, mas `git rm --cached` e reescrita de histórico são destrutivos e exigem coordenação com a equipe. Rotacionar segredos pode derrubar integrações até atualizar os ambientes.',
          },
          createdAt: new Date(),
        })
      }
    } else if (!this.gitignoreCoversEnv(gitignore)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'env-not-gitignored', location: '.gitignore' }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'high',
        title: 'Arquivos .env não ignorados pelo Git',
        description: 'Existe um .gitignore mas ele não ignora arquivos .env. Um .env com credenciais reais pode ser commitado por acidente.',
        evidence: '.gitignore não contém uma entrada que cubra `.env`',
        recommendation: 'Adicione `.env` (e variantes como `.env.local`) ao .gitignore antes que credenciais sejam versionadas.',
        proposedFix: {
          description: 'Adicione uma linha `.env` ao .gitignore.',
          riskOfApplying: 'Baixo risco. Se um .env já estiver versionado, adicioná-lo ao .gitignore não o remove do histórico — é preciso `git rm --cached` e rotacionar os segredos expostos.',
        },
        createdAt: new Date(),
      })
    }

    const envExample = await this.readFileSafe(join(repoPath, '.env.example'))
    if (envExample === null) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'no-env-example', location: '.env.example' }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'low',
        title: 'Sem .env.example',
        description: 'Não existe um .env.example documentando as variáveis de ambiente necessárias. Sem ele, é comum compartilhar um .env real (com segredos).',
        evidence: 'Arquivo .env.example ausente no repositório',
        recommendation: 'Crie um .env.example listando as chaves esperadas com valores placeholder (ex.: `API_KEY=`), sem segredos reais.',
        proposedFix: {
          description: 'Crie um .env.example com as chaves esperadas e valores vazios/placeholder.',
          riskOfApplying: 'Risco nulo: arquivo de documentação. Apenas garanta que não contenha valores reais.',
        },
        createdAt: new Date(),
      })
    } else if (this.envExampleHasRealValues(envExample)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'env-example-has-values', location: '.env.example' }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'medium',
        title: '.env.example contém valores reais',
        description: 'O .env.example parece conter valores reais em vez de placeholders. Um .env.example deve documentar as chaves, não expor segredos.',
        evidence: '.env.example tem linhas KEY=valor com valores não-placeholder',
        recommendation: 'Substitua os valores do .env.example por placeholders vazios (ex.: `API_KEY=`) e rotacione qualquer segredo que tenha vazado por ali.',
        proposedFix: {
          description: 'Esvazie os valores no .env.example (mantenha só as chaves) e rotacione segredos expostos.',
          riskOfApplying: 'Baixo risco editar o arquivo; o risco real é o segredo já exposto — rotacione-o no provedor.',
        },
        createdAt: new Date(),
      })
    }

    return findings
  }

  /**
   * Lista arquivos .env (`.env`, `.env.*`) presentes diretamente na raiz do repositório.
   * Usado apenas quando `.gitignore` está ausente para detectar o pior cenário.
   */
  private async findEnvFiles(repoPath: string): Promise<string[]> {
    try {
      const entries = await readdir(repoPath)
      // Match .env and .env.* variants (e.g. .env.local, .env.production) but
      // explicitly exclude .env.example — that file is documentation, not a secret store.
      return entries.filter(name =>
        name === '.env' || (/^\.env\..+$/.test(name) && name !== '.env.example'),
      )
    } catch {
      return []
    }
  }

  private async readFileSafe(path: string): Promise<string | null> {
    try {
      return await readFile(path, 'utf8')
    } catch {
      return null
    }
  }

  /** True se o .gitignore tem alguma entrada que cobre `.env`. */
  private gitignoreCoversEnv(content: string): boolean {
    return content
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'))
      .some(l => {
        const normalized = l.replace(/^\//, '').replace(/\/$/, '')
        // Cobre: `.env`, `.env*`, `*.env`, `**/.env`
        return normalized === '.env'
          || normalized === '.env*'
          || normalized === '*.env'
          || normalized.endsWith('/.env')
          || /^\.env\*?$/.test(normalized)
      })
  }

  /**
   * Heurística: o .env.example tem linhas `KEY=valor` com valor não-vazio e que
   * não parece placeholder. Tolerante a comentários e linhas em branco.
   */
  private envExampleHasRealValues(content: string): boolean {
    const lines = content.split(/\r?\n/)
    for (const raw of lines) {
      const line = raw.trim()
      if (!line || line.startsWith('#')) continue
      const eq = line.indexOf('=')
      if (eq <= 0) continue
      let value = line.slice(eq + 1).trim()
      // Remove aspas envolventes para avaliar o conteúdo.
      value = value.replace(/^["']|["']$/g, '').trim()
      if (!value) continue // KEY= → placeholder vazio, ok
      if (this.looksLikePlaceholder(value)) continue
      return true
    }
    return false
  }

  private looksLikePlaceholder(value: string): boolean {
    const v = value.toLowerCase()
    // Placeholders típicos: your-key-here, changeme, xxx, <...>, ${...}, exemplo...
    if (/^<.*>$/.test(value)) return true
    if (/^\$\{.*\}$/.test(value)) return true
    if (/^x+$/i.test(value)) return true
    const placeholderWords = [
      'your', 'change', 'changeme', 'placeholder', 'example', 'exemplo',
      'todo', 'fixme', 'replace', 'sua-', 'seu-', 'dummy', 'fake', 'sample',
      'xxxx', 'aqui', 'here', 'optional', 'true', 'false', 'localhost',
    ]
    return placeholderWords.some(w => v.includes(w))
  }
}
