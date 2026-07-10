import { readdir, readFile, stat } from 'node:fs/promises'
import { join, relative } from 'node:path'
import type {
  SecurityAgent, ScanScope, Finding, AgentCategory, Severity, ProposedFix,
} from '@fracta/core'
import { SkippedCheck, stableFindingId } from '@fracta/core'
import { parsePrismaModels, buildInventory, detectOperators, type InventoryEntry, type OperatorMatch } from './lgpd-inventory.js'
import { findPolicyDoc, diffPolicyVsCode } from './lgpd-policy.js'

// __tests__ e benchmark-repo = fixtures deliberadamente vulneráveis (o gerador do benchmark
// em docs/benchmark-repo PLANTA segredos/SQLi/log sensível de propósito — não é superfície de
// produção; escaneá-los é ruído e faz o dogfood do próprio Fracta gritar contra o fixture);
// fracta-reports = saída do próprio scanner (escanear o próprio relatório é ruído).
// .worktrees/.claude = git worktrees (Claude Code): re-escanear duplica achados (#40).
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', '.next', 'coverage', '.turbo', '__tests__', 'fracta-reports', 'benchmark-repo', '.worktrees', '.claude'])

// Extensões de texto que vale a pena escanear (código + config). Binários são ignorados.
const TEXT_EXT = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
  '.json', '.prisma', '.env', '.yaml', '.yml', '.vue', '.svelte',
])

// Docs coletados APENAS para a conferência política×código (Check 7). Não alimentam os
// checks de código (um README com `console.log(cpf)` num code-fence não é vazamento real).
const DOC_EXT = new Set(['.md', '.mdx', '.html', '.htm'])

function extOf(relPath: string): string {
  const dot = relPath.lastIndexOf('.')
  return dot < 0 ? '' : relPath.slice(dot).toLowerCase()
}

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

/**
 * "Code view" da linha: zera o CONTEÚDO de literais de string ('...', "...", `...`),
 * preservando a estrutura de código. Usado para (a) rejeitar um `console.log(` que está
 * DENTRO de uma string (exemplo em blog/docs — não é logging real) e (b) descartar o termo
 * sensível que aparece só na PROSA da mensagem ("[Diagnostic] ...Token"), mantendo os
 * identificadores logados. Interpolações `${...}` são tratadas à parte (são o valor logado).
 */
function stripStringLiterals(s: string): string {
  return s
    .replace(/`(?:\\.|\$\{[^}]*\}|[^`\\])*`/g, ' ') // template literal completo (interpolações à parte)
    .replace(/'(?:\\.|[^'\\])*'/g, ' ')             // '...'
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')             // "..."
    .replace(/[`'"][^`'"]*$/g, ' ')                 // string não fechada na linha (multi-linha)
}

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
      // Docs (.md/.html) só servem ao Check 7 (política×código); não passam pelos checks de código.
      if (DOC_EXT.has(extOf(file.relPath))) continue

      const lines = file.content.split(/\r?\n/)

      if (SENSITIVE_TERM.test(file.content)) mentionsSensitiveAnywhere = true
      if (TLS_SIGNAL.test(file.content)) hasTlsSignal = true

      // Check 2 (sinal): senha + escrita no DB no mesmo arquivo.
      if (PASSWORD_TERM.test(file.content) && DB_WRITE.test(file.content)) {
        hasPasswordWrite = true
      }

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

        // ---- Check 3: isolamento de tenant — query PERTO de dado sensível ----
        // ROUND 3 (Veredicto): antes o gate era file-level (`SENSITIVE_TERM.test(file.content)`),
        // então UMA menção incidental a "token" (publicShareToken) ou "benefício" (numa string de
        // prompt) num service de 1400 linhas classificava o arquivo inteiro como sensível e flaggava
        // TODOS os findMany (39 FP num só arquivo). Agora exige o termo sensível na VIZINHANÇA da
        // query — o achado passa a significar "esta query específica toca dado sensível e não escopa
        // por tenant", que é o que a evidência sempre afirmou. Preserva recall (o dado sensível
        // legítimo costuma estar no select/where/comentário da própria query).
        if (PRISMA_FIND.test(line) && this.hasSensitiveTermNearby(lines, i)) {
          if (!this.hasTenantScopeNearby(lines, i)) {
            findings.push(this.tenantIsolation(scope, file.relPath, lineNo))
          }
        }
      }
    }

    // ---- Check 2: senhas sem hashing ----
    // MONOREPO: procura a lib de hashing em TODOS os package.json do repo (não só a raiz).
    // Em zap-api o bcrypt está em `backend/package.json` — ler só a raiz gerava FP.
    if (hasPasswordWrite && !this.hasHashingLibInAnyPackageJson(files)) {
      findings.push(this.passwordNoHashing(scope))
    }

    // ---- Check 4: criptografia em trânsito/repouso não evidenciada ----
    if (mentionsSensitiveAnywhere && !hasTlsSignal) {
      findings.push(this.encryptionUnclear(scope))
    }

    // ---- Check 5: LGPD ancorada no CÓDIGO — inventário de dados (rascunho de ROPA) ----
    const prismaText = files.filter(f => f.relPath.endsWith('.prisma')).map(f => f.content).join('\n')
    if (prismaText.trim()) {
      const inventory = buildInventory(parsePrismaModels(prismaText))
      if (inventory.length) findings.push(this.dataInventory(scope, inventory))
    }

    // ---- Check 6: operadores/sub-processadores + transferência internacional (Art. 33) ----
    const opMap = new Map<string, OperatorMatch>()
    for (const f of files) {
      if (f.relPath === 'package.json' || f.relPath.endsWith('/package.json')) {
        for (const op of detectOperators(f.content)) if (!opMap.has(op.name)) opMap.set(op.name, op)
      }
    }
    if (opMap.size) {
      const operators = Array.from(opMap.values())
      findings.push(this.operatorsMapping(scope, operators))

      // ---- Check 7: divergência POLÍTICA×CÓDIGO — confere a política publicada ----
      const policy = findPolicyDoc(files)
      if (policy) {
        const div = diffPolicyVsCode(policy, operators)
        if (div.hasInternationalOps) {
          if (div.internationalDenied) {
            // Pior caso da marca "não mente": a política AFIRMA que não transfere ao exterior
            // enquanto o código o faz. Contradição direta — mais grave que a mera omissão.
            findings.push(this.intlTransferContradicted(scope, policy.relPath, operators.filter(o => o.international)))
          } else if (!div.internationalDisclosed) {
            findings.push(this.intlTransferUndisclosed(scope, policy.relPath, operators.filter(o => o.international)))
          }
        }
        if (div.undeclaredOperators.length) {
          findings.push(this.operatorsUndeclared(scope, policy.relPath, div.undeclaredOperators))
        }
        // Completude da política (dimensões code-detectáveis da revisão DPO): Encarregado (Art. 41)
        // e direitos do titular (Art. 18). Conservador — só nudge INFO quando a política EXISTE mas
        // não menciona o item. Fecha 2 das 16 dimensões que antes eram só sinal de score, não achado.
        if (!div.declaresDpo) {
          findings.push(this.policyMissingDpo(scope, policy.relPath))
        }
        if (!div.declaresDataSubjectRights) {
          findings.push(this.policyMissingRights(scope, policy.relPath))
        }
      } else {
        findings.push(this.policyNotFound(scope, operators))
      }
    }

    return findings
  }

  // -------------------------------------------------------------------------
  // Check 7 — divergência política×código (materializa o diferencial LGPD-nativo)
  // -------------------------------------------------------------------------
  private intlTransferContradicted(scope: ScanScope, policyPath: string, intlOps: OperatorMatch[]): Finding {
    const rule = 'lgpd-policy-intl-contradicted'
    const names = intlOps.map(o => o.name).join(', ')
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'medium' as Severity, // mais grave que a omissão (low): a política CONTRADIZ o código
      confidence: 'low', // heurística de negação — pede confirmação humana antes de agir
      title: `Transferência internacional NEGADA na política, mas o código a realiza (Art. 33)`,
      description:
        'CONFERI A POLÍTICA PUBLICADA CONTRA O CÓDIGO e encontrei uma CONTRADIÇÃO DIRETA. A política ' +
        `de privacidade (${policyPath}) AFIRMA que NÃO há transferência internacional (ou que os dados ` +
        `permanecem no Brasil), mas o código usa operadores que processam dados fora do Brasil (${names}) ` +
        '— o que configura TRANSFERÊNCIA INTERNACIONAL (Art. 33 da LGPD). Uma política que NEGA o que o ' +
        'código faz é pior que uma omissa: induz o titular a erro. HEURÍSTICA — a detecção de negação é ' +
        'aproximada; CONFIRME o texto da política antes de agir (a declaração pode estar segmentada).',
      evidence: `Política conferida: ${policyPath}. A política NEGA transferência internacional / afirma retenção no Brasil, mas há operadores internacionais no código: ${names}.`,
      recommendation:
        'Corrija a contradição: ou (a) a Política de Privacidade passa a DECLARAR a transferência ' +
        'internacional ancorada numa hipótese do Art. 33 (cláusulas-padrão da ANPD, país adequado, etc.) ' +
        `e lista os operadores no exterior (${names}); ou (b) elimine a transferência internacional de ` +
        'fato (operador nacional/self-hosted). Manter a negação enquanto o código transfere expõe o ' +
        'controlador a sanção por informação enganosa ao titular (Art. 6º, VI — transparência).',
      createdAt: new Date(),
    }
  }

  private intlTransferUndisclosed(scope: ScanScope, policyPath: string, intlOps: OperatorMatch[]): Finding {
    const rule = 'lgpd-policy-intl-undisclosed'
    const names = intlOps.map(o => o.name).join(', ')
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'low' as Severity,
      confidence: 'low', // heurística: a política pode declarar em outra página/genericamente
      title: `Transferência internacional não declarada na política (Art. 33)`,
      description:
        'CONFERI A POLÍTICA PUBLICADA CONTRA O CÓDIGO. O projeto usa operadores que processam ' +
        `dados fora do Brasil (${names}), o que configura TRANSFERÊNCIA INTERNACIONAL (Art. 33 da ` +
        `LGPD), mas a política de privacidade encontrada (${policyPath}) não contém nenhuma menção ` +
        'a transferência internacional / dados fora do Brasil. HEURÍSTICA — a declaração pode estar ' +
        'em outra página; confirme antes de agir.',
      evidence: `Política conferida: ${policyPath}. Operadores internacionais no código: ${names}. Nenhuma menção a "transferência internacional"/"fora do Brasil" na política.`,
      recommendation:
        'Declare a transferência internacional na Política de Privacidade, ancorada numa hipótese ' +
        'do Art. 33 (cláusulas-padrão da ANPD, país com nível adequado, etc.) e liste os operadores ' +
        'no exterior. Este é um requisito de transparência, não opcional.',
      createdAt: new Date(),
    }
  }

  private operatorsUndeclared(scope: ScanScope, policyPath: string, ops: OperatorMatch[]): Finding {
    const rule = 'lgpd-policy-operators-undeclared'
    const names = ops.map(o => o.name).join(', ')
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'low' as Severity,
      confidence: 'low', // conservador: só acusa quando NEM o nome NEM sinônimos aparecem na política
      title: `Operadores no código ausentes da política de privacidade`,
      description:
        'CONFERI A POLÍTICA PUBLICADA CONTRA O CÓDIGO. Estes operadores/sub-processadores são usados ' +
        `pelo projeto (deps) mas o nome deles não aparece na política encontrada (${policyPath}):\n` +
        ops.map(o => `• ${o.name} (${o.purpose})${o.international ? ' — transferência internacional' : ''}`).join('\n') +
        '\n\nHEURÍSTICA CONSERVADORA — a política pode descrevê-los genericamente (ex.: "provedores de ' +
        'nuvem"). Reveja se cada tratamento está transparente ao titular (Art. 9º).',
      evidence: `Política conferida: ${policyPath}. Operadores não citados nominalmente: ${names}.`,
      recommendation:
        'Liste nominalmente os operadores/sub-processadores na Política de Privacidade (Art. 9º/Art. 39), ' +
        'com finalidade e, quando no exterior, a base de transferência internacional. Isso torna o ' +
        'tratamento transparente e verificável pelo titular.',
      createdAt: new Date(),
    }
  }

  private policyMissingDpo(scope: ScanScope, policyPath: string): Finding {
    const rule = 'lgpd-policy-missing-dpo'
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'low' as Severity,
      confidence: 'low', // heurística de texto: o canal do encarregado pode estar em outra página
      title: `Política não declara o Encarregado/DPO (Art. 41)`,
      description:
        `CONFERI A POLÍTICA PUBLICADA (${policyPath}). Não encontrei menção a Encarregado/DPO nem a ` +
        'um canal de contato do encarregado pelo tratamento de dados. O Art. 41 da LGPD exige que o ' +
        'controlador INDIQUE um encarregado e publique a identidade e o canal de contato. HEURÍSTICA ' +
        '— o canal pode estar em outra página (ex.: "Fale conosco"); confirme antes de agir.',
      evidence: `Política conferida: ${policyPath}. Sem menção a "encarregado"/"DPO"/canal do encarregado.`,
      recommendation:
        'Publique na Política de Privacidade a identidade e o canal de contato do Encarregado (DPO) ' +
        'pelo tratamento de dados pessoais (Art. 41 da LGPD).',
      createdAt: new Date(),
    }
  }

  private policyMissingRights(scope: ScanScope, policyPath: string): Finding {
    const rule = 'lgpd-policy-missing-rights'
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'low' as Severity,
      confidence: 'low', // heurística de texto: os direitos podem estar descritos com outras palavras
      title: `Política não descreve os direitos do titular / como exercê-los (Art. 18)`,
      description:
        `CONFERI A POLÍTICA PUBLICADA (${policyPath}). Não encontrei descrição clara dos direitos do ` +
        'titular (acesso, correção, exclusão/eliminação, portabilidade, revogação de consentimento) ' +
        'nem de como exercê-los. O Art. 18 da LGPD assegura esses direitos e a política deve informar ' +
        'como o titular os exerce. HEURÍSTICA CONSERVADORA — confirme; os direitos podem estar ' +
        'descritos com outras palavras.',
      evidence: `Política conferida: ${policyPath}. Sem sinal claro de "direitos do titular"/exercício de direitos.`,
      recommendation:
        'Descreva na Política de Privacidade os direitos do titular (Art. 18) e o canal/procedimento ' +
        'para exercê-los (acesso, correção, eliminação, portabilidade, revogação de consentimento).',
      createdAt: new Date(),
    }
  }

  private policyNotFound(scope: ScanScope, operators: OperatorMatch[]): Finding {
    const rule = 'lgpd-policy-not-found'
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'info' as Severity,
      title: `Divergência política×código não verificável — política não localizada no repositório`,
      description:
        `Detectei ${operators.length} operador(es)/sub-processador(es) no código, mas não localizei ` +
        'uma Política de Privacidade dentro do repositório para conferir automaticamente o que o ' +
        'código faz contra o que a política declara. HONESTIDADE: não afirmo que a política inexiste ' +
        '— ela pode estar hospedada fora do repo (CMS, site institucional). A conferência ' +
        'política×código não pôde ser executada.',
      evidence: `Operadores no código: ${operators.map(o => o.name).join(', ')}. Nenhum documento de política de privacidade encontrado no repositório.`,
      recommendation:
        'Para permitir a conferência automática, versione a Política de Privacidade no repositório ' +
        '(página ou markdown). Independentemente disso, garanta que a política publicada declare os ' +
        'operadores e a transferência internacional (Art. 9º/Art. 33).',
      createdAt: new Date(),
    }
  }

  // -------------------------------------------------------------------------
  // Check 5 — inventário de dados pessoais ancorado no schema (rascunho de ROPA)
  // -------------------------------------------------------------------------
  private dataInventory(scope: ScanScope, inv: InventoryEntry[]): Finding {
    const rule = 'lgpd-data-inventory'
    const totalSens = inv.reduce((n, e) => n + e.sensivel.length, 0)
    const lines = inv.map(e => {
      const parts = [
        e.sensivel.length ? `sensível: ${e.sensivel.join(', ')}` : '',
        e.pessoal.length ? `pessoal: ${e.pessoal.join(', ')}` : '',
      ].filter(Boolean)
      return `• ${e.model} → ${parts.join(' | ')}`
    })
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'info' as Severity,
      title: `Inventário de dados pessoais ancorado no schema (rascunho de ROPA) — ${inv.length} modelos, ${totalSens} campos sensíveis`,
      description:
        'Li o schema Prisma e montei o esqueleto de um INVENTÁRIO DE DADOS / ROPA (Art. 37) ' +
        'ancorado no seu código — não num formulário auto-declarado. Modelos com dado pessoal:\n' +
        lines.join('\n') +
        '\n\nHeurística determinística por nome de campo (zero IA) — pode ter falso-positivo/negativo. ' +
        'Cada tratamento ainda precisa de finalidade, base legal e retenção (o julgamento jurídico).',
      evidence: `${inv.length} modelos com dado pessoal; ${totalSens} campos classificados como sensíveis (Art. 5º, II).`,
      recommendation:
        'Use isto como ponto de partida do ROPA: para cada modelo/finalidade, defina base legal ' +
        '(Art. 7º/11), prazo de retenção (Art. 15/16) e compartilhamentos. Dado sensível exige ' +
        'base do Art. 11 e cuidado agravado.',
      createdAt: new Date(),
    }
  }

  // -------------------------------------------------------------------------
  // Check 6 — operadores/sub-processadores + transferência internacional (Art. 33)
  // -------------------------------------------------------------------------
  private operatorsMapping(scope: ScanScope, ops: OperatorMatch[]): Finding {
    const rule = 'lgpd-operators-transfer'
    const intl = ops.filter(o => o.international)
    const lines = ops.map(o => `• ${o.name} (${o.purpose})${o.international ? ' — transferência internacional' : ''}`)
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: 'info' as Severity,
      title: `Operadores/sub-processadores detectados no código — ${ops.length} (${intl.length} com transferência internacional)`,
      description:
        'Mapeei operadores/sub-processadores pelas dependências do projeto (Art. 39). ' +
        'Cada um trata dado pessoal por sua conta e precisa de contrato (DPA):\n' +
        lines.join('\n') +
        (intl.length
          ? `\n\n⚠️ ${intl.length} implicam TRANSFERÊNCIA INTERNACIONAL de dados (Art. 33) — que precisa ser declarada na política e ancorada numa hipótese (cláusulas-padrão da ANPD, país adequado, etc.).`
          : '') +
        '\n\nHeurística por nome de pacote — confirme a stack real e os contratos.',
      evidence: `Operadores: ${ops.map(o => o.name).join(', ')}. Transferência internacional: ${intl.map(o => o.name).join(', ') || 'nenhuma detectada'}.`,
      recommendation:
        'Garanta um DPA com cada operador (Art. 39), liste os sub-processadores, e declare a ' +
        'transferência internacional na Política de Privacidade ancorada numa hipótese do Art. 33.',
      createdAt: new Date(),
    }
  }

  // -------------------------------------------------------------------------
  // Check 1 — dado sensível em log (risco-chave LGPD)
  // SANITIZAÇÃO: nunca ecoa o valor logado. A evidence é só `relPath:line`
  // mais o termo sensível que casou (nome de variável/chave), jamais o conteúdo.
  // -------------------------------------------------------------------------
  private matchSensitiveLog(line: string): SensitiveLogHit | null {
    // 1) É uma chamada de log REAL? Testamos na "code view" (strings zeradas): um
    //    `console.log(` dentro de uma string (exemplo de código em blog/docs) some aqui.
    const code = stripStringLiterals(line)
    const callIdxCode = code.search(LOG_CALL)
    if (callIdxCode < 0) return null

    // 2) Só os ARGUMENTOS da chamada (parênteses balanceados) — não o resto da linha.
    //    Descarta prosa/HTML/comentário DEPOIS do fechamento (FP do blog: "...cartão..."
    //    após `console.log("API on")`).
    const rawParen = line.indexOf('(', line.search(LOG_CALL))
    if (rawParen < 0) return null
    const rawArgs = this.extractCallArgs(line, rawParen)

    // 3) Um termo sensível só conta se for um VALOR LOGADO, não a prosa da mensagem:
    //    (a) identificador em código, fora de string (`user.cpf`);
    //    (b) dentro de uma interpolação `${...}` (o valor logado);
    //    (c) rótulo colado a uma interpolação (`token=${t}`, `Senha: ${x}` — o rótulo revela o valor).
    const interpolations = Array.from(rawArgs.matchAll(/\$\{([^}]*)\}/g)).map(m => m[1]).join(' ')
    const codeArgs = stripStringLiterals(rawArgs)
    const adjacentLabels = Array.from(rawArgs.matchAll(/([\p{L}]+)\s*[:=]\s*\$\{/gu)).map(m => m[1]).join(' ')
    const haystack = `${interpolations} ${codeArgs} ${adjacentLabels}`

    const matches = haystack.match(SENSITIVE_TERM_GLOBAL)
    if (!matches || matches.length === 0) return null
    // termos únicos, normalizados em minúsculas — não inclui valores.
    const term = Array.from(new Set(matches.map(m => m.toLowerCase()))).join(', ')
    return { relPath: '', line: 0, term }
  }

  /** Argumentos de uma chamada a partir do '(' de abertura (parênteses balanceados na linha). */
  private extractCallArgs(line: string, openParen: number): string {
    let depth = 0
    for (let i = openParen; i < line.length; i++) {
      const c = line[i]
      if (c === '(') depth++
      else if (c === ')') { depth--; if (depth === 0) return line.slice(openParen + 1, i) }
    }
    return line.slice(openParen + 1) // não fechou na linha (chamada multi-linha) → até o fim
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
  /** Procura uma lib de hashing em QUALQUER package.json do repo (monorepo-aware). */
  private hasHashingLibInAnyPackageJson(files: ScannedFile[]): boolean {
    for (const f of files) {
      if (f.relPath !== 'package.json' && !f.relPath.endsWith('/package.json')) continue
      let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
      try {
        pkg = JSON.parse(f.content)
      } catch {
        continue
      }
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }
      if (HASHING_LIBS.some(lib => lib in deps)) return true
    }
    return false
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
      confidence: 'low', // heurística conservadora (hashing pode ser externo) — avisa, não derruba
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

  /**
   * Termo sensível na VIZINHANÇA da query (janela simétrica ±6 linhas). Substitui o gate
   * file-level do Check 3: o dado sensível relevante para isolamento de tenant aparece no
   * select/where/comentário da própria query — não a 700 linhas de distância numa string de
   * prompt. Corta o FP em massa (round 3) sem perder o caso real (query que de fato manipula
   * CPF/senha/processo sem escopo).
   */
  private hasSensitiveTermNearby(lines: string[], idx: number): boolean {
    const start = Math.max(0, idx - 6)
    const end = Math.min(lines.length, idx + 7)
    for (let i = start; i < end; i++) {
      if (SENSITIVE_TERM.test(lines[i])) return true
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
      confidence: 'low', // heurística p/ revisão humana (pode ser RLS/middleware ou query global)
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
      confidence: 'low', // heurística conservadora (TLS pode terminar no proxy/LB) — avisa, não derruba
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
    const ext = name.slice(dot).toLowerCase()
    return TEXT_EXT.has(ext) || DOC_EXT.has(ext) // DOC_EXT só p/ o Check 7 (política×código)
  }
}
