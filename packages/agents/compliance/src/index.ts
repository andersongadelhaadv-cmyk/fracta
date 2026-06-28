import { readdir, readFile, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'
import type {
  SecurityAgent, ScanScope, Finding, AgentCategory, Severity, ProposedFix,
} from '@fracta/core'
import { SkippedCheck, stableFindingId } from '@fracta/core'

const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', '.next', 'coverage', '.turbo'])

// Extensões de texto que vale a pena escanear (código + config). Binários são ignorados.
const TEXT_EXT = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
  '.json', '.prisma', '.env', '.yaml', '.yml', '.vue', '.svelte',
])

const MAX_FILE_BYTES = 2_000_000 // não tenta ler arquivos enormes (ex.: bundles, lockfiles gigantes)

/**
 * Identificadores de dado pessoal sensível sob a LGPD no contexto desta família
 * de produtos (jurídico/previdenciário brasileiro). CPF/CNIS/dados previdenciários
 * e processos criminais são DADO SENSÍVEL (art. 5º, II) → responsabilização agravada.
 */
const SENSITIVE_TERM =
  /\b(cpf|cnpj|cnis|rg|senha|password|passwd|token|processo|prontuario|prontuário|nis|pis|cartao|cartão|beneficio|benefício)\b/i

// Mesma regex, mas global, para extrair QUAL termo casou (sem expor o valor logado).
const SENSITIVE_TERM_GLOBAL =
  /\b(cpf|cnpj|cnis|rg|senha|password|passwd|token|processo|prontuario|prontuário|nis|pis|cartao|cartão|beneficio|benefício)\b/gi

// Chamadas de log: console.log/error/info e logger.*( / this.logger.*(
const LOG_CALL =
  /(?:console\.(?:log|error|info|warn|debug)|(?:this\.)?logger\.\w+)\s*\(/i

// Libs de hashing aceitáveis para senhas.
const HASHING_LIBS = ['bcrypt', 'bcryptjs', 'argon2', '@node-rs/argon2', 'scrypt']

// Heurística "tem auth": menção a password perto de uma escrita/criação no DB.
const PASSWORD_TERM = /\bpassword|senha|passwd\b/i
const DB_WRITE = /\b(create|createMany|insert|insertInto|save|update|upsert|INSERT\s+INTO)\b/i

// Prisma findMany/findFirst (potencial vazamento cross-tenant em arquivo sensível).
const PRISMA_FIND = /\.(findMany|findFirst)\s*\(/
const TENANT_SCOPE = /tenantId|ownerId|accountId|orgId/i

// Sinais de TLS/HTTPS/cookie seguro/HSTS.
const TLS_SIGNAL = /https:\/\/|\bsecure\s*:\s*true\b|helmet|hsts|strict-transport-security|forceSSL|requireHTTPS/i

interface ScannedFile {
  relPath: string
  content: string
}

interface SensitiveLogHit {
  relPath: string
  line: number
  term: string
}

export class ComplianceAgent implements SecurityAgent {
  name = 'COMPLIANCE Agent'
  category: AgentCategory = 'compliance'
  concurrency = 1
  timeoutMs = 60_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const repoPath = scope.target.repoPath
    if (!repoPath) {
      throw new SkippedCheck('sem repoPath — ComplianceAgent precisa do repositório local (read-only)')
    }

    const findings: Finding[] = []
    const files = await this.collectFiles(repoPath)

    // Estado agregado para os checks de repositório inteiro.
    let mentionsSensitiveAnywhere = false
    let hasTlsSignal = false
    let hasPasswordWrite = false

    for (const file of files) {
      const lines = file.content.split(/\r?\n/)

      if (SENSITIVE_TERM.test(file.content)) mentionsSensitiveAnywhere = true
      if (TLS_SIGNAL.test(file.content)) hasTlsSignal = true

      // Check 2 (sinal): senha + escrita no DB no mesmo arquivo.
      if (PASSWORD_TERM.test(file.content) && DB_WRITE.test(file.content)) {
        hasPasswordWrite = true
      }

      const fileMentionsSensitive = SENSITIVE_TERM.test(file.content)

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const lineNo = i + 1

        // ---- Check 1: dado sensível em log ----
        if (LOG_CALL.test(line)) {
          const hit = this.matchSensitiveLog(line)
          if (hit) {
            findings.push(this.sensitiveInLog(scope, file.relPath, lineNo, hit))
          }
        }

        // ---- Check 3: isolamento de tenant em arquivo com dado sensível ----
        if (fileMentionsSensitive && PRISMA_FIND.test(line)) {
          if (!this.hasTenantScopeNearby(lines, i)) {
            findings.push(this.tenantIsolation(scope, file.relPath, lineNo))
          }
        }
      }
    }

    // ---- Check 2: senhas sem hashing ----
    if (hasPasswordWrite) {
      const hashingLib = await this.findHashingLib(repoPath)
      if (!hashingLib) {
        findings.push(this.passwordNoHashing(scope))
      }
    }

    // ---- Check 4: criptografia em trânsito/repouso não evidenciada ----
    if (mentionsSensitiveAnywhere && !hasTlsSignal) {
      findings.push(this.encryptionUnclear(scope))
    }

    return findings
  }

  // -------------------------------------------------------------------------
  // Check 1 — dado sensível em log (risco-chave LGPD)
  // SANITIZAÇÃO: nunca ecoa o valor logado. A evidence é só `relPath:line`
  // mais o termo sensível que casou (nome de variável/chave), jamais o conteúdo.
  // -------------------------------------------------------------------------
  private matchSensitiveLog(line: string): SensitiveLogHit | null {
    // só os argumentos da chamada de log (depois do primeiro "(")
    const callIdx = line.search(LOG_CALL)
    const parenIdx = line.indexOf('(', callIdx)
    const args = parenIdx >= 0 ? line.slice(parenIdx + 1) : line
    const matches = args.match(SENSITIVE_TERM_GLOBAL)
    if (!matches || matches.length === 0) return null
    // termos únicos, normalizados em minúsculas — não inclui valores.
    const term = Array.from(new Set(matches.map(m => m.toLowerCase()))).join(', ')
    return { relPath: '', line: 0, term }
  }

  private sensitiveInLog(scope: ScanScope, relPath: string, line: number, hit: SensitiveLogHit): Finding {
    const rule = `sensitive-in-log:${relPath}:${line}`
    const proposedFix: ProposedFix = {
      description:
        'Remova o dado sensível do log ou aplique mascaramento/redação antes de logar ' +
        '(ex.: logar apenas um id de correlação, ou mascarar CPF como ***.***.***-**). ' +
        'Prefira um logger estruturado com redação automática de campos sensíveis.',
      riskOfApplying:
        'PROPOSTA — não aplicada. Alterar logs pode reduzir a observabilidade usada em ' +
        'debugging/auditoria; confirme com a equipe que nenhum fluxo depende daquele valor ' +
        'em texto plano antes de remover.',
    }
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule, location: relPath }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'high' as Severity,
      title: `Possível dado sensível em log: ${relPath}:${line}`,
      description:
        'Dado sensível pode estar sendo gravado em log em texto plano (LGPD). ' +
        'A chamada de log nesta linha referencia um identificador sensível ' +
        `(termo casado: ${hit.term}). Dados como CPF/CNIS/dados previdenciários e ` +
        'processos criminais são DADO SENSÍVEL sob a LGPD (art. 5º, II), com ' +
        'responsabilização agravada se vazados via logs.',
      // SANITIZADO: apenas arquivo:linha + termo. Nunca o valor logado.
      evidence: `${relPath}:${line} (termo sensível: ${hit.term})`,
      recommendation:
        'Nunca registre dado sensível em texto plano. Mascare ou remova o valor do log ' +
        '(LGPD art. 6º — segurança/prevenção; art. 46 — medidas de segurança). ' +
        'Dado previdenciário/criminal é dado sensível: o vazamento por log acarreta ' +
        'responsabilização agravada do controlador.',
      proposedFix,
      createdAt: new Date(),
    }
  }

  // -------------------------------------------------------------------------
  // Check 2 — senhas sem hashing
  // -------------------------------------------------------------------------
  private async findHashingLib(repoPath: string): Promise<string | null> {
    let pkgRaw: string
    try {
      pkgRaw = await readFile(join(repoPath, 'package.json'), 'utf-8')
    } catch {
      return null // sem package.json → não dá pra confirmar lib; deixa o check rodar
    }
    let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
    try {
      pkg = JSON.parse(pkgRaw)
    } catch {
      return null
    }
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }
    for (const lib of HASHING_LIBS) {
      if (lib in deps) return lib
    }
    return null
  }

  private passwordNoHashing(scope: ScanScope): Finding {
    const rule = 'password-no-hashing'
    const proposedFix: ProposedFix = {
      description:
        'Use uma função de hashing forte para senhas (ex.: argon2 ou bcrypt) antes de ' +
        'persistir. Nunca armazene senha em texto plano nem com hash reversível/MD5/SHA1.',
      command: 'npm install argon2',
      riskOfApplying:
        'PROPOSTA — não aplicada. Requer migração das senhas existentes (re-hash no próximo ' +
        'login) e ajuste do fluxo de verificação. Aplicar sem cuidado pode travar logins. ' +
        'CONFIRMAÇÃO HUMANA obrigatória: a heurística é conservadora e pode haver hashing ' +
        'feito por um serviço externo (ex.: provider de auth) não visível no package.json.',
    }
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'high' as Severity,
      title: 'Possível armazenamento de senha sem hashing',
      description:
        'O repositório aparenta ter autenticação (menção a senha/password próxima de uma ' +
        'escrita/criação no banco), mas nenhuma biblioteca de hashing ' +
        `(${HASHING_LIBS.join(', ')}) consta nas dependências do package.json. ` +
        'Senhas sem hashing forte violam medidas de segurança esperadas pela LGPD ' +
        '(art. 46). HEURÍSTICA CONSERVADORA — exige confirmação humana, pois o hashing ' +
        'pode ocorrer fora deste repositório (provider de auth gerenciado).',
      evidence: 'package.json sem bcrypt/bcryptjs/argon2/@node-rs/argon2/scrypt + escrita de senha detectada no código.',
      recommendation:
        'Confirme manualmente como as senhas são armazenadas. Se forem persistidas por este ' +
        'serviço, aplique argon2/bcrypt. LGPD art. 46 exige medidas técnicas adequadas para ' +
        'proteger dados pessoais — credenciais comprometidas costumam expor dado sensível dos titulares.',
      proposedFix,
      createdAt: new Date(),
    }
  }

  // -------------------------------------------------------------------------
  // Check 3 — isolamento de tenant em arquivos com dado sensível (heurística)
  // -------------------------------------------------------------------------
  private hasTenantScopeNearby(lines: string[], idx: number): boolean {
    // janela: a própria linha + até 6 linhas seguintes (where costuma vir junto/abaixo).
    const end = Math.min(lines.length, idx + 7)
    for (let i = idx; i < end; i++) {
      if (TENANT_SCOPE.test(lines[i])) return true
    }
    return false
  }

  private tenantIsolation(scope: ScanScope, relPath: string, line: number): Finding {
    const rule = `tenant-isolation-sensitive:${relPath}:${line}`
    const proposedFix: ProposedFix = {
      description:
        'Adicione um filtro de tenant/owner no `where` da query (ex.: ' +
        '`where: { tenantId: user.tenantId, ... }`) para garantir que apenas dados do ' +
        'titular/organização correta sejam retornados.',
      riskOfApplying:
        'PROPOSTA — não aplicada. É uma HEURÍSTICA: a query pode já ser legitimamente global ' +
        '(ex.: rota administrativa) ou o escopo pode ser aplicado em outra camada (RLS, ' +
        'middleware). Adicionar where indevido pode esconder dados esperados. Revisão humana obrigatória.',
    }
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule, location: relPath }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'low' as Severity,
      title: `Query sem escopo de tenant em arquivo com dado sensível: ${relPath}:${line}`,
      description:
        'HEURÍSTICA PARA REVISÃO HUMANA. Uma chamada Prisma findMany/findFirst nesta linha ' +
        'não referencia tenantId/ownerId/accountId/orgId nas linhas próximas, e o arquivo ' +
        'manipula dado sensível. Cruza com a verificação de tenant do StackAgent, mas aqui ' +
        'restrita a arquivos que tocam dado sensível — onde a falta de isolamento implica ' +
        'exposição de DADO SENSÍVEL sob a LGPD (responsabilização agravada). Pode ser falso ' +
        'positivo se o escopo for aplicado por RLS/middleware ou se a query for legitimamente global.',
      evidence: `${relPath}:${line} — findMany/findFirst sem where com tenantId/ownerId/accountId/orgId nas proximidades.`,
      recommendation:
        'Verifique manualmente se a query é multi-tenant. Se for, escope por tenant/owner do ' +
        'usuário autenticado. LGPD: vazamento cross-tenant de dado sensível (previdenciário/' +
        'criminal/CPF) gera responsabilização agravada do controlador.',
      proposedFix,
      createdAt: new Date(),
    }
  }

  // -------------------------------------------------------------------------
  // Check 4 — criptografia em trânsito/repouso não evidenciada (heurística)
  // -------------------------------------------------------------------------
  private encryptionUnclear(scope: ScanScope): Finding {
    const rule = 'encryption-unclear'
    const proposedFix: ProposedFix = {
      description:
        'Garanta TLS/HTTPS de ponta a ponta (HSTS via helmet, cookies com `secure: true`, ' +
        'redirecionamento http→https) e avalie criptografia em repouso para os campos sensíveis.',
      riskOfApplying:
        'PROPOSTA — não aplicada. É uma HEURÍSTICA conservadora: TLS pode estar terminado no ' +
        'proxy/load balancer (nginx, Cloudflare) fora deste repositório. Forçar HTTPS/HSTS ' +
        'incorretamente pode quebrar ambientes de dev. Verificação humana obrigatória.',
    }
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'low' as Severity,
      title: 'Criptografia em trânsito/repouso não evidenciada',
      description:
        'O repositório manipula dado sensível, mas não foi encontrado sinal de TLS/HTTPS ' +
        'forçado (sem `https`, sem cookie `secure: true`, sem HSTS/helmet) no código. ' +
        'HEURÍSTICA CONSERVADORA — requer verificação humana: a terminação TLS pode ocorrer ' +
        'em proxy/LB (nginx, Cloudflare) fora deste repositório. Sob a LGPD (art. 46), dados ' +
        'sensíveis (previdenciário/criminal/CPF) exigem medidas de segurança como criptografia ' +
        'em trânsito e, quando aplicável, em repouso.',
      evidence: 'Repositório com dado sensível e sem evidência em código de TLS/HTTPS/secure cookie/HSTS.',
      recommendation:
        'Confirme manualmente que todo tráfego é HTTPS (TLS no app ou no proxy) e que cookies ' +
        'de sessão usam `secure`/`httpOnly`. Avalie criptografia em repouso para campos ' +
        'sensíveis. LGPD art. 46 exige medidas técnicas proporcionais ao risco — dado sensível ' +
        'eleva o padrão exigido.',
      proposedFix,
      createdAt: new Date(),
    }
  }

  // -------------------------------------------------------------------------
  // File walking (espelha o DocsAgent: ignora IGNORE_DIRS, tolera erros por arquivo)
  // -------------------------------------------------------------------------
  private async collectFiles(repoPath: string): Promise<ScannedFile[]> {
    const files: ScannedFile[] = []
    await this.walkDir(repoPath, repoPath, files)
    return files
  }

  private async walkDir(dir: string, baseDir: string, files: ScannedFile[]): Promise<void> {
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
        } else if (this.isTextFile(entry) && info.size <= MAX_FILE_BYTES) {
          const content = await readFile(fullPath, 'utf-8')
          files.push({
            relPath: relative(baseDir, fullPath).replace(/\\/g, '/'),
            content,
          })
        }
      } catch {
        /* permissão, arquivo removido, ou leitura falhou — tolera por arquivo */
      }
    }
  }

  private isTextFile(name: string): boolean {
    // package.json e .env(.x) entram pelo nome; o resto pela extensão.
    if (name === 'package.json') return true
    if (name.startsWith('.env')) return true
    const dot = name.lastIndexOf('.')
    if (dot < 0) return false
    return TEXT_EXT.has(name.slice(dot).toLowerCase())
  }
}
