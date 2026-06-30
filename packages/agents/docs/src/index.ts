import { readdir, readFile, stat } from 'fs/promises'
import { join, relative } from 'path'
import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { stableFindingId, SkippedCheck } from '@fracta/core'

const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', '.next', 'coverage', '.turbo', '__tests__', 'fracta-reports'])
const LEGACY_PATTERNS = /old|legado|legacy|deprecated|backup|v1\.|_old\.|antigo/i
const MS_IN_DAY = 86_400_000

interface DocFile {
  path: string
  content: string
  modifiedAt: Date
  relativePath: string
}

export class DocsAgent implements SecurityAgent {
  name = 'DOCS Agent'
  category: AgentCategory = 'docs'
  concurrency = 1
  timeoutMs = 60_000

  /**
   * `explicitRepoPath` é um override (ex.: o comando `fracta docs --docs-path`).
   * No `scan`, fica indefinido e o repo vem de `target.repoPath`. SEM nenhum dos
   * dois, o agente PULA (SkippedCheck) — jamais cai no `process.cwd()`, que
   * escanearia o próprio Fracta e produziria achados desonestos.
   */
  constructor(private readonly explicitRepoPath?: string) {}

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []

    const repoPath = this.explicitRepoPath ?? scope.target.repoPath
    if (!repoPath) {
      throw new SkippedCheck(
        'DOCS Agent: sem repoPath no target — defina `repoPath` para auditar a documentação do repositório.',
      )
    }

    try {
      const files = await this.collectMarkdownFiles(repoPath)

      if (files.length === 0) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'docs-none' }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: 'info',
          title: 'Nenhum arquivo .md encontrado',
          description: `Nenhum arquivo Markdown encontrado em ${repoPath}`,
          recommendation: 'Adicione documentação Markdown ao repositório.',
          createdAt: new Date(),
        })
        return findings
      }

      const h1Titles = new Map<string, string[]>()

      for (const file of files) {
        await this.auditFile(scope, file, findings, h1Titles)
      }

      this.checkDuplicateTitles(scope, h1Titles, findings)
    } catch (err) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'docs-read-error' }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'info',
        title: 'DOCS Agent — erro ao ler repositório',
        description: `Erro ao escanear ${repoPath}: ${String(err)}`,
        recommendation: 'Verifique se o caminho do repositório está correto.',
        createdAt: new Date(),
      })
    }

    return findings
  }

  private async auditFile(
    scope: ScanScope,
    file: DocFile,
    findings: Finding[],
    h1Titles: Map<string, string[]>
  ): Promise<void> {
    const ageMs = Date.now() - file.modifiedAt.getTime()
    const ageDays = Math.floor(ageMs / MS_IN_DAY)

    if (ageDays > 180) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-stale:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'medium',
        title: `Documentação obsoleta: ${file.relativePath}`,
        description: `Arquivo não modificado há ${ageDays} dias (>180 dias).`,
        endpoint: file.relativePath,
        recommendation: 'Revise e atualize o arquivo ou adicione uma nota de depreciação no topo.',
        createdAt: new Date(),
      })
    }

    if (LEGACY_PATTERNS.test(file.relativePath)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-legacy-name:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'medium',
        title: `Arquivo com nome legado: ${file.relativePath}`,
        description: 'Nome do arquivo sugere conteúdo legado, backup ou depreciado.',
        endpoint: file.relativePath,
        recommendation: 'Remova o arquivo se for obsoleto, ou renomeie e documente o status atual.',
        createdAt: new Date(),
      })
    }

    if (/TODO|FIXME/i.test(file.content)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-todo:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'low',
        title: `TODOs não resolvidos: ${file.relativePath}`,
        description: 'Arquivo contém marcações TODO ou FIXME indicando documentação incompleta.',
        endpoint: file.relativePath,
        recommendation: 'Resolva os TODOs ou abra issues para rastreá-los.',
        createdAt: new Date(),
      })
    }

    const v1Matches = (file.content.match(/\bv[01]\b/gi) ?? []).length
    if (v1Matches > 2) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-legacy-version-refs:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'medium',
        title: `Referências a versões legadas: ${file.relativePath}`,
        description: `${v1Matches} referências a v0/v1 encontradas. Pode indicar documentação desatualizada.`,
        endpoint: file.relativePath,
        recommendation: 'Verifique se as referências a versões antigas são intencionais ou precisam ser atualizadas.',
        createdAt: new Date(),
      })
    }

    const h1Match = file.content.match(/^#\s+(.+)$/m)
    if (h1Match) {
      const title = h1Match[1].trim()
      const existing = h1Titles.get(title) ?? []
      h1Titles.set(title, [...existing, file.relativePath])
    }
  }

  private checkDuplicateTitles(
    scope: ScanScope,
    h1Titles: Map<string, string[]>,
    findings: Finding[]
  ): void {
    for (const [title, paths] of h1Titles) {
      if (paths.length > 1) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-duplicate-h1:${title}` }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: 'low',
          title: `Título H1 duplicado: "${title}"`,
          description: `O mesmo título H1 aparece em ${paths.length} arquivos: ${paths.join(', ')}`,
          recommendation: 'Use títulos únicos para facilitar navegação e indexação.',
          createdAt: new Date(),
        })
      }
    }
  }

  private async collectMarkdownFiles(dir: string): Promise<DocFile[]> {
    const files: DocFile[] = []
    await this.walkDir(dir, dir, files)
    return files
  }

  private async walkDir(dir: string, baseDir: string, files: DocFile[]): Promise<void> {
    let entries: string[]
    try {
      entries = await readdir(dir)
    } catch { return }

    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue
      const fullPath = join(dir, entry)

      try {
        const info = await stat(fullPath)
        if (info.isDirectory()) {
          await this.walkDir(fullPath, baseDir, files)
        } else if (entry.endsWith('.md')) {
          const content = await readFile(fullPath, 'utf-8')
          files.push({
            path: fullPath,
            content,
            modifiedAt: info.mtime,
            relativePath: relative(baseDir, fullPath).replace(/\\/g, '/'),
          })
        }
      } catch { /* permissão ou arquivo removido — ignora */ }
    }
  }
}
