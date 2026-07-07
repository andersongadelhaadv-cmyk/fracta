import { readdir, readFile, stat } from 'fs/promises'
import { join, relative, basename } from 'path'
import type {
  SecurityAgent, ScanScope, Finding, AgentCategory, Severity, ProposedFix,
} from '@fracta/core'
import { SkippedCheck, stableFindingId } from '@fracta/core'

// __tests__ = fixtures deliberadamente vulneráveis (não é superfície de produção);
// fracta-reports = saída do próprio scanner (escanear o próprio relatório é ruído).
// .worktrees/.claude = git worktrees (Claude Code): re-escanear duplica achados (#40).
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', '.next', 'coverage', '.turbo', '__tests__', 'fracta-reports', '.worktrees', '.claude'])

// Lê apenas arquivos de texto relevantes (código + config + env). Determinístico, read-only.
const TEXT_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|json)$/i
const ENV_FILE = /(^|[\\/])\.env($|\.[^\\/]+$)/i
const NEXT_CONFIG = /(^|[\\/])next\.config\.(js|ts|mjs|cjs)$/i

interface SourceFile {
  /** Caminho relativo normalizado (POSIX) para evidência estável. */
  relPath: string
  content: string
  lines: string[]
  /** true quando o arquivo é .env* ou next.config.* (onde segredos legitimamente ficam). */
  isEnvLike: boolean
}

interface FindingInput {
  rule: string
  /** Chave de localização (string) usada só para o id estável. */
  location?: string
  /** Localização ESTRUTURADA (arquivo + linha) → vira `Finding.location` → SARIF region. */
  at?: { file: string; line?: number }
  /** Referências (CWE/OWASP) → alimentam o scorecard OWASP e o SARIF. */
  references?: string[]
  severity: Severity
  title: string
  description: string
  evidence?: string
  recommendation: string
  proposedFix?: ProposedFix
}

/**
 * StackAgent — SAST determinístico (regex/string puro) + checks de frontend.
 *
 * Read-only SEMPRE: apenas lê arquivos sob `scope.target.repoPath`. Nunca aplica nada;
 * correções são apenas PROPOSTAS (`proposedFix.riskOfApplying` obrigatório).
 *
 * Checks: helmet ausente, SQL raw com concatenação, ValidationPipe (ausente/sem whitelist),
 * rate limiting (throttler), isolamento de tenant (heurística p/ revisão humana) e
 * frontend (segredos NEXT_PUBLIC_, CORS wildcard, chaves de provider hardcoded).
 *
 * `skipped` (nunca falso "seguro") quando falta repoPath.
 */
export class StackAgent implements SecurityAgent {
  name = 'STACK Agent'
  category: AgentCategory = 'code'
  concurrency = 1
  timeoutMs = 60_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const repoPath = scope.target.repoPath
    if (!repoPath) {
      throw new SkippedCheck('sem repoPath — StackAgent precisa do repositório local para SAST')
    }

    const sources = await this.collectFiles(repoPath)
    const pkg = await this.readPackageJson(repoPath)
    const isNest = this.detectNest(sources, pkg)

    const out: FindingInput[] = []

    this.checkHelmet(sources, isNest, out)
    this.checkRawSql(sources, out)
    this.checkValidationPipe(sources, isNest, out)
    this.checkRateLimiting(sources, isNest, pkg, out)
    this.checkTenantIsolation(sources, out)
    this.checkNextPublicSecrets(sources, out)
    this.checkCorsWildcard(sources, out)
    this.checkHardcodedKeys(sources, out)

    return out.map(f => this.toFinding(scope, f))
  }

  // ---------------------------------------------------------------- helpers

  private toFinding(scope: ScanScope, f: FindingInput): Finding {
    return {
      id: stableFindingId({
        saas: scope.target.name,
        camada: this.category,
        rule: f.rule,
        location: f.location,
      }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: f.severity,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      location: f.at,
      recommendation: f.recommendation,
      references: f.references,
      proposedFix: f.proposedFix,
      createdAt: new Date(),
    }
  }

  private async readPackageJson(repoPath: string): Promise<Record<string, unknown> | null> {
    try {
      const raw = await readFile(join(repoPath, 'package.json'), 'utf-8')
      return JSON.parse(raw) as Record<string, unknown>
    } catch {
      return null
    }
  }

  /** Deps + devDeps achatadas em um único conjunto de nomes. */
  private allDeps(pkg: Record<string, unknown> | null): Set<string> {
    const names = new Set<string>()
    if (!pkg) return names
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
      const block = pkg[field]
      if (block && typeof block === 'object') {
        for (const name of Object.keys(block as Record<string, unknown>)) names.add(name)
      }
    }
    return names
  }

  private detectNest(sources: SourceFile[], pkg: Record<string, unknown> | null): boolean {
    const hasMain = sources.some(s => /(^|\/)main\.ts$/.test(s.relPath))
    if (hasMain) return true
    for (const dep of this.allDeps(pkg)) {
      if (dep.startsWith('@nestjs/')) return true
    }
    return false
  }

  private mainTsFiles(sources: SourceFile[]): SourceFile[] {
    return sources.filter(s => /(^|\/)main\.ts$/.test(s.relPath))
  }

  /** Nº da linha (1-based) onde `index` (offset em chars) cai no conteúdo. */
  private lineAt(content: string, index: number): number {
    let line = 1
    for (let i = 0; i < index && i < content.length; i++) {
      if (content[i] === '\n') line++
    }
    return line
  }

  // ---------------------------------------------------------------- checks

  // 1) Helmet ausente (NestJS sem app.use(helmet()) em nenhum main.ts).
  private checkHelmet(sources: SourceFile[], isNest: boolean, out: FindingInput[]): void {
    if (!isNest) return
    const mains = this.mainTsFiles(sources)
    if (mains.length === 0) return
    const hasHelmet = mains.some(s => /helmet\s*\(/.test(s.content))
    if (hasHelmet) return

    out.push({
      rule: 'helmet-missing',
      severity: 'medium',
      title: 'Helmet ausente no bootstrap NestJS',
      description:
        'Aplicação NestJS detectada mas nenhuma chamada a `helmet(` foi encontrada no(s) main.ts. ' +
        'Sem Helmet, headers de segurança (HSTS, X-Content-Type-Options, etc.) não são aplicados.',
      evidence: `${mains.map(m => m.relPath).join(', ')} — nenhuma chamada helmet() encontrada`,
      recommendation: 'Adicione `app.use(helmet())` no bootstrap, após criar a app.',
      proposedFix: {
        description: "Importe helmet e registre como middleware global: `import helmet from 'helmet'` e `app.use(helmet())` antes de `app.listen(...)`.",
        diff: "import helmet from 'helmet'\n// ...\napp.use(helmet())",
        command: 'npm install helmet',
        riskOfApplying:
          'Os defaults de CSP do Helmet podem bloquear assets inline (scripts/estilos) e recursos de terceiros. ' +
          'Revise/ajuste a política de CSP antes de subir em produção para não quebrar o frontend.',
      },
    })
  }

  // 2) SQL raw com concatenação ($queryRawUnsafe/$executeRawUnsafe sempre; $queryRaw(/$executeRaw( com + ou template como arg normal).
  private checkRawSql(sources: SourceFile[], out: FindingInput[]): void {
    const unsafe = /\$(?:query|execute)RawUnsafe\s*\(/g
    // chamada normal (parêntese) — a forma SEGURA é tagged template SEM parêntese: $queryRaw`...`
    const rawCall = /\$(?:query|execute)Raw\s*\(([^)]*)/g

    for (const file of sources) {
      let m: RegExpExecArray | null

      while ((m = unsafe.exec(file.content)) !== null) {
        const line = this.lineAt(file.content, m.index)
        out.push(this.rawSqlFinding(file, line, m[0].replace(/\s*\($/, ''), 'API unsafe ($queryRawUnsafe/$executeRawUnsafe)'))
      }

      while ((m = rawCall.exec(file.content)) !== null) {
        const args = m[1]
        const hasConcat = args.includes('+')
        const hasInterpolation = /`[^`]*\$\{[^}]*\}[^`]*`/.test(args)
        if (!hasConcat && !hasInterpolation) continue
        const line = this.lineAt(file.content, m.index)
        out.push(
          this.rawSqlFinding(
            file,
            line,
            file.lines[line - 1]?.trim() ?? m[0],
            hasConcat ? 'concatenação de string (+)' : 'template literal interpolado passado como argumento',
          ),
        )
      }
    }
  }

  private rawSqlFinding(file: SourceFile, line: number, snippet: string, how: string): FindingInput {
    return {
      rule: `raw-sql-concat:${file.relPath}:${line}`,
      location: file.relPath,
      at: { file: file.relPath, line },
      references: ['https://cwe.mitre.org/data/definitions/89.html', 'A03:2021 - Injection'],
      severity: 'high',
      title: `Risco de SQL injection (SQL raw): ${file.relPath}:${line}`,
      description:
        `SQL bruto construído via ${how}. Isso permite injeção de SQL. ` +
        'A forma SEGURA é o tagged template `prisma.$queryRaw`...`` (sem parêntese), que parametriza as interpolações automaticamente.',
      evidence: `${file.relPath}:${line} — ${snippet.slice(0, 200)}`,
      recommendation:
        'Use o tagged template `prisma.$queryRaw`SELECT ... WHERE id = ${id}`` (parametrizado) ' +
        'ou `Prisma.sql`/`$queryRawUnsafe` apenas com `Prisma.sql` e placeholders. Nunca concatene input do usuário.',
      proposedFix: {
        description:
          'Converta para tagged template parametrizado: troque `prisma.$queryRawUnsafe("... " + id)` por ' +
          '`prisma.$queryRaw`SELECT ... WHERE id = ${id}``.',
        riskOfApplying:
          'A reescrita muda a forma da chamada; valide que a query continua válida e que os tipos das interpolações ' +
          'são suportados pelo driver. Teste a query após a conversão.',
      },
    }
  }

  // 3) ValidationPipe ausente (NestJS) ou sem whitelist:true.
  private checkValidationPipe(sources: SourceFile[], isNest: boolean, out: FindingInput[]): void {
    const usages = sources.filter(s => /ValidationPipe/.test(s.content))

    if (usages.length === 0) {
      if (!isNest) return
      out.push({
        rule: 'validationpipe-missing',
        severity: 'medium',
        title: 'NestJS sem ValidationPipe global',
        description:
          'Aplicação NestJS detectada mas nenhum uso de `ValidationPipe` foi encontrado. ' +
          'Sem ela, DTOs não são validados e propriedades não declaradas passam direto para os handlers.',
        recommendation:
          'Registre `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))` no bootstrap.',
        proposedFix: {
          description:
            'No main.ts: `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))`.',
          diff: 'app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))',
          riskOfApplying:
            'Com `whitelist`/`forbidNonWhitelisted`, requests que enviam campos extras passam a falhar (400). ' +
            'Pode quebrar clientes que mandam payloads maiores que o DTO. Audite os contratos antes.',
        },
      })
      return
    }

    // Existe ValidationPipe — checa se algum uso tem whitelist: true por perto (mesma "janela" do arquivo).
    const hasWhitelist = usages.some(s => {
      const idx = s.content.indexOf('ValidationPipe')
      const window = s.content.slice(idx, idx + 400)
      return /whitelist\s*:\s*true/.test(window) || /whitelist\s*:\s*true/.test(s.content)
    })
    if (hasWhitelist) return

    const first = usages[0]
    const line = this.lineAt(first.content, first.content.indexOf('ValidationPipe'))
    out.push({
      rule: 'validationpipe-no-whitelist',
      location: first.relPath,
      at: { file: first.relPath, line },
      severity: 'medium',
      title: 'ValidationPipe sem whitelist: true',
      description:
        'O `ValidationPipe` é usado mas sem `whitelist: true`. Sem whitelist, propriedades não declaradas no DTO ' +
        'não são removidas, abrindo espaço para mass-assignment.',
      evidence: `${first.relPath}:${line} — ValidationPipe sem whitelist: true`,
      recommendation: 'Configure `new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`.',
      proposedFix: {
        description: 'Adicione `whitelist: true` (e idealmente `forbidNonWhitelisted: true`) às opções do ValidationPipe.',
        diff: 'new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })',
        riskOfApplying:
          'Requests com campos extras passarão a ser rejeitados/limpos. Pode afetar clientes existentes — valide os payloads aceitos.',
      },
    })
  }

  // 4) Rate limiting (NestJS sem @nestjs/throttler nas deps e sem ThrottlerModule no código).
  private checkRateLimiting(
    sources: SourceFile[],
    isNest: boolean,
    pkg: Record<string, unknown> | null,
    out: FindingInput[],
  ): void {
    if (!isNest) return
    const deps = this.allDeps(pkg)
    const hasDep = deps.has('@nestjs/throttler')
    const usesModule = sources.some(s => /ThrottlerModule/.test(s.content))
    if (hasDep || usesModule) return

    out.push({
      rule: 'throttler-missing',
      severity: 'medium',
      title: 'Sem rate limiting (@nestjs/throttler ausente)',
      description:
        'Aplicação NestJS sem `@nestjs/throttler` nas dependências e sem uso de `ThrottlerModule`. ' +
        'Rotas de login ficam expostas a brute force e rotas de LLM/IA a abuso com impacto FINANCEIRO direto ' +
        '(cada chamada custa tokens) e DoS de custo.',
      recommendation:
        'Adicione `@nestjs/throttler`, registre o `ThrottlerModule.forRoot(...)` e aplique limites mais estritos ' +
        'em rotas de login e em endpoints que disparam chamadas a LLM/provedores pagos.',
      proposedFix: {
        description:
          'Instale e configure: `ThrottlerModule.forRoot([{ ttl: 60000, limit: 10 }])` no AppModule e ' +
          '`@Throttle({ default: { limit: 5, ttl: 60000 } })` em rotas sensíveis (login, IA).',
        command: 'npm install @nestjs/throttler',
        riskOfApplying:
          'Limites mal calibrados podem bloquear tráfego legítimo (falsos 429). Calibre por rota e ' +
          'considere identidade/tenant na chave do throttler, não só IP.',
      },
    })
  }

  // 5) Isolamento de tenant — HEURÍSTICA conservadora p/ revisão humana (severity low).
  private checkTenantIsolation(sources: SourceFile[], out: FindingInput[]): void {
    const finders = /\.(findMany|findFirst|findUnique)\s*\(/g
    const tenantKey = /tenantid|ownerid|accountid|orgid/i

    for (const file of sources) {
      let m: RegExpExecArray | null
      while ((m = finders.exec(file.content)) !== null) {
        const line = this.lineAt(file.content, m.index)
        // Janela ao redor da chamada: ~300 chars antes/depois para olhar o `where`.
        const start = Math.max(0, m.index - 300)
        const window = file.content.slice(start, m.index + 400)
        const hasWhere = /where/i.test(window)
        const hasTenant = tenantKey.test(window)
        // Só sinaliza quando há where SEM chave de tenant, ou nenhuma menção a tenant na vizinhança.
        if (hasTenant) continue
        out.push({
          rule: `tenant-isolation-review:${file.relPath}:${line}`,
          location: file.relPath,
          at: { file: file.relPath, line },
          references: ['https://cwe.mitre.org/data/definitions/639.html', 'A01:2021 - Broken Access Control'],
          severity: 'low',
          title: `Possível falta de isolamento de tenant (heurística): ${file.relPath}:${line}`,
          description:
            `HEURÍSTICA (requer revisão humana): consulta Prisma \`${m[1]}\` ${hasWhere ? 'com `where` mas' : 'sem `where` e'} ` +
            'sem referência a `tenantId|ownerId|accountId|orgId` na vizinhança. ' +
            'Pode haver vazamento entre tenants — ou pode ser uma query legítimamente global. Confirme manualmente.',
          evidence: `${file.relPath}:${line} — ${file.lines[line - 1]?.trim().slice(0, 160) ?? m[0]}`,
          recommendation:
            'Confirme que a query é escopada ao tenant/owner (filtro no `where` ou Prisma extension/RLS). ' +
            'Se for intencionalmente global, suprima este finding.',
          proposedFix: {
            description:
              'Adicione o escopo de tenant no `where` (ex.: `where: { tenantId: ctx.tenantId, ... }`) ou ' +
              'aplique uma Prisma client extension/Postgres RLS que force o filtro em todas as queries.',
            riskOfApplying:
              'É uma heurística: pode ser falso-positivo (query global legítima). Aplicar um filtro de tenant ' +
              'numa query que deveria ser global esconderia dados. Revise antes de mudar.',
          },
        })
      }
    }
  }

  // 6a) Segredos NEXT_PUBLIC_ em .env*/next.config.* cujo NOME parece segredo.
  private checkNextPublicSecrets(sources: SourceFile[], out: FindingInput[]): void {
    const secretName = /KEY|SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL/i
    // captura NEXT_PUBLIC_<NAME> em atribuições (env ou next.config)
    const re = /\bNEXT_PUBLIC_([A-Z0-9_]+)\b/g

    for (const file of sources) {
      if (!file.isEnvLike) continue
      const seen = new Set<string>()
      let m: RegExpExecArray | null
      while ((m = re.exec(file.content)) !== null) {
        const suffix = m[1]
        const varName = `NEXT_PUBLIC_${suffix}`
        if (seen.has(varName)) continue
        if (!secretName.test(varName)) continue
        seen.add(varName)
        const line = this.lineAt(file.content, m.index)
        out.push({
          rule: `next-public-secret:${varName}`,
          location: file.relPath,
          at: { file: file.relPath, line },
          references: ['https://cwe.mitre.org/data/definitions/200.html', 'A01:2021 - Broken Access Control'],
          severity: 'high',
          title: `Segredo exposto via NEXT_PUBLIC_: ${varName}`,
          description:
            `A variável \`${varName}\` (em ${file.relPath}) usa o prefixo \`NEXT_PUBLIC_\`. ` +
            'No Next.js, tudo com esse prefixo é EMBUTIDO no bundle do cliente e fica PÚBLICO — visível a qualquer ' +
            'visitante. O nome sugere que isto é um segredo, então ele está efetivamente vazado.',
          evidence: `${file.relPath}:${line} — ${varName} (valor omitido)`,
          recommendation:
            'Remova o prefixo `NEXT_PUBLIC_` deste segredo e consuma-o apenas no servidor (route handlers, server actions, API). ' +
            'Rotacione a credencial, pois ela pode já ter sido buildada para o cliente.',
          proposedFix: {
            description:
              `Renomeie \`${varName}\` para \`${suffix}\` (sem o prefixo) e mova o uso para o lado servidor. ` +
              'Rotacione a chave comprometida.',
            riskOfApplying:
              'Remover o prefixo torna a variável indisponível no código do cliente — qualquer uso client-side ' +
              'quebrará e precisa ser movido para o servidor. Rotacionar a chave invalida a antiga em uso.',
          },
        })
      }
    }
  }

  // 6b) CORS wildcard: origin: '*' / origin: true, ou Access-Control-Allow-Origin: '*'.
  private checkCorsWildcard(sources: SourceFile[], out: FindingInput[]): void {
    const patterns: RegExp[] = [
      /origin\s*:\s*['"`]\*['"`]/g,
      /origin\s*:\s*true\b/g,
      /['"`]Access-Control-Allow-Origin['"`]\s*[,:]\s*['"`]\*['"`]/g,
    ]

    for (const file of sources) {
      if (file.isEnvLike) continue
      for (const re of patterns) {
        re.lastIndex = 0
        let m: RegExpExecArray | null
        while ((m = re.exec(file.content)) !== null) {
          const line = this.lineAt(file.content, m.index)
          out.push({
            rule: `cors-wildcard:${file.relPath}:${line}`,
            location: file.relPath,
            at: { file: file.relPath, line },
            references: ['https://cwe.mitre.org/data/definitions/942.html', 'A05:2021 - Security Misconfiguration'],
            severity: 'high',
            title: `CORS permissivo (wildcard): ${file.relPath}:${line}`,
            description:
              'Configuração de CORS com origem curinga (`*` ou `true`). Isso permite que qualquer site faça ' +
              'requisições autenticadas ao backend; combinado com credenciais, expõe a API a CSRF/exfiltração cross-origin.',
            evidence: `${file.relPath}:${line} — ${file.lines[line - 1]?.trim().slice(0, 160) ?? m[0]}`,
            recommendation:
              'Restrinja a origem a uma allowlist explícita dos domínios do frontend. Nunca combine origem `*` com `credentials: true`.',
            proposedFix: {
              description:
                "Troque por allowlist: `app.enableCors({ origin: ['https://app.seu-dominio.com'], credentials: true })`.",
              diff: "origin: ['https://app.seu-dominio.com']",
              riskOfApplying:
                'Restringir a origem pode bloquear front-ends/ambientes legítimos não listados (ex.: preview/staging). ' +
                'Liste todos os domínios válidos antes de aplicar.',
            },
          })
        }
      }
    }
  }

  // 6c) Chaves de provider hardcoded em source (não .env). Evidência MASCARADA.
  private checkHardcodedKeys(sources: SourceFile[], out: FindingInput[]): void {
    const patterns: Array<{ re: RegExp; label: string }> = [
      { re: /sk_live_[A-Za-z0-9]{6,}/g, label: 'Stripe live secret key' },
      { re: /sk_test_[A-Za-z0-9]{6,}/g, label: 'Stripe test secret key' },
      { re: /AIza[0-9A-Za-z_\-]{20,}/g, label: 'Google API key' },
    ]

    for (const file of sources) {
      if (file.isEnvLike) continue // .env é onde segredos DEVEM ficar — aqui caçamos só em source/src
      if (!/(^|\/)src\//.test(file.relPath)) continue
      for (const { re, label } of patterns) {
        re.lastIndex = 0
        let m: RegExpExecArray | null
        while ((m = re.exec(file.content)) !== null) {
          const key = m[0]
          const line = this.lineAt(file.content, m.index)
          out.push({
            rule: `hardcoded-key:${file.relPath}:${line}`,
            location: file.relPath,
            at: { file: file.relPath, line },
            references: ['https://cwe.mitre.org/data/definitions/798.html', 'A07:2021 - Identification and Authentication Failures'],
            severity: 'high',
            title: `Chave de provider hardcoded (${label}): ${file.relPath}:${line}`,
            description:
              `Uma ${label} aparece embutida no código-fonte (${file.relPath}). Segredos em source são commitados, ` +
              'distribuídos e frequentemente buildados para o cliente — trate como comprometidos.',
            evidence: `${file.relPath}:${line} — ${this.maskKey(key)}`,
            recommendation:
              'Mova a chave para variável de ambiente (server-side) e rotacione-a imediatamente, pois já está no histórico do git.',
            proposedFix: {
              description: 'Substitua o literal por `process.env.NOME_DA_CHAVE` e rotacione a credencial no provedor.',
              riskOfApplying:
                'Remover o literal exige que a variável de ambiente esteja configurada em todos os ambientes, ' +
                'senão a integração quebra em runtime. Rotacionar invalida a chave antiga em uso.',
            },
          })
        }
      }
    }
  }

  /** Mascara a chave: mostra só os primeiros 7 chars + '…'. Nunca ecoa o segredo inteiro. */
  private maskKey(key: string): string {
    return `${key.slice(0, 7)}…`
  }

  // ---------------------------------------------------------------- walk

  private async collectFiles(repoPath: string): Promise<SourceFile[]> {
    const files: SourceFile[] = []
    await this.walkDir(repoPath, repoPath, files)
    return files
  }

  private async walkDir(dir: string, baseDir: string, files: SourceFile[]): Promise<void> {
    let entries: string[]
    try {
      entries = await readdir(dir)
    } catch {
      return
    }

    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue
      const fullPath = join(dir, entry)

      try {
        const info = await stat(fullPath)
        if (info.isDirectory()) {
          await this.walkDir(fullPath, baseDir, files)
          continue
        }
        if (!this.isReadableFile(fullPath, entry)) continue
        const content = await readFile(fullPath, 'utf-8')
        const relPath = relative(baseDir, fullPath).replace(/\\/g, '/')
        const name = basename(entry)
        files.push({
          relPath,
          content,
          lines: content.split(/\r?\n/),
          isEnvLike: ENV_FILE.test(name) || NEXT_CONFIG.test(name),
        })
      } catch {
        /* permissão, binário ilegível ou arquivo removido — tolera por-arquivo */
      }
    }
  }

  private isReadableFile(fullPath: string, entry: string): boolean {
    const name = basename(entry)
    if (ENV_FILE.test(name)) return true
    if (NEXT_CONFIG.test(name)) return true
    return TEXT_FILE.test(name)
  }
}
