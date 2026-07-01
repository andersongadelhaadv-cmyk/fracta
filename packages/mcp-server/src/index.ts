import { readFile } from 'fs/promises'
import { parse as parseYaml } from 'yaml'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { FractaOrchestrator } from '@fracta/core'
import type { Target, ScanReport, ScanDepth, TargetHealth } from '@fracta/core'
import { PassiveScanner } from '@fracta/web-scan'
import { AuthAgent } from '@fracta/agent-auth'
import { HeadersAgent } from '@fracta/agent-headers'
import { IdorAgent } from '@fracta/agent-idor'
import { DocsAgent } from '@fracta/agent-docs'
import { TenantAgent } from '@fracta/agent-tenant'
import { RaceAgent } from '@fracta/agent-race'
import { StripeAgent } from '@fracta/agent-stripe'
import { DependenciesAgent } from '@fracta/agent-dependencies'
import { SecretsAgent } from '@fracta/agent-secrets'
import { StackAgent } from '@fracta/agent-stack'
import { InfraAgent } from '@fracta/agent-infra'
import { ComplianceAgent } from '@fracta/agent-compliance'
import { NestJSSkill } from '@fracta/skill-nestjs'
import { PrismaSkill } from '@fracta/skill-prisma'
import { SupabaseSkill } from '@fracta/skill-supabase'
import { FractaReporter } from '@fracta/reporter'
import { SqliteFindingStore } from '@fracta/store'
import { LlmEnricher } from '@fracta/llm'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'

// ── Auto-elevação para Node 22+ (estado entre runs no MCP) ──────────────────────
// O store usa `node:sqlite`, builtin só em Node >=22.5. Quando o cliente MCP invoca
// este server sob um Node mais antigo (ex.: o Node 20 de sistema da VPS), re-executa
// o processo sob um Node 22 ESCOPADO se houver um disponível — assim regressão/supressão
// ligam sem depender do config do cliente (que pode estar fora do nosso alcance).
// Guard `FRACTA_REEXEC` evita loop. No-op se já há node:sqlite (Node>=22.5) ou se nenhum
// binário Node 22 for encontrado (ex.: dev local Windows) → segue sem estado (degradação graciosa).
function hasNodeSqlite(): boolean {
  try {
    createRequire(import.meta.url)('node:sqlite')
    return true
  } catch {
    return false
  }
}
if (!process.env.FRACTA_REEXEC && !hasNodeSqlite()) {
  const node22 = [process.env.FRACTA_NODE, '/opt/node-22/bin/node']
    .filter((p): p is string => Boolean(p))
    .find((p) => existsSync(p))
  if (node22 && process.argv[1]) {
    const res = spawnSync(node22, [process.argv[1], ...process.argv.slice(2)], {
      stdio: 'inherit',
      env: { ...process.env, FRACTA_REEXEC: '1' },
    })
    process.exit(res.status ?? 0)
  }
}

const TARGETS_CONFIG = process.env.TARGETS_CONFIG ?? './configs/targets.yaml'

// Estado entre execuções compartilhado por toda a sessão MCP (stdio = processo longo).
// Opcional: se o store não puder ser criado (Node < 22.5 sem node:sqlite, fs read-only),
// o servidor sobe sem estado — a detecção nunca depende da persistência (regra Fase 2).
let store: SqliteFindingStore | undefined
try {
  store = new SqliteFindingStore(process.env.FRACTA_STATE ?? './fracta-state.db')
} catch (err) {
  console.error(`[Fracta] Estado entre runs indisponível: ${(err as Error).message}`)
  console.error(`[Fracta] MCP seguindo SEM regressão/supressão (detecção intacta).`)
}

// Borda LLM no MCP: OPT-IN via FRACTA_LLM=1. A chave (ANTHROPIC_API_KEY) costuma
// viver no config do cliente MCP, então ligar por padrão gastaria tokens (Opus) em
// TODO scan_target silenciosamente. Default: SEM LLM (zero tokens) — detecção intacta.
const enricher = process.env.FRACTA_LLM === '1' ? new LlmEnricher() : undefined

async function loadTargets(): Promise<Target[]> {
  const raw = await readFile(TARGETS_CONFIG, 'utf-8')
  const resolved = raw.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] ?? '')
  const parsed = parseYaml(resolved) as { targets: Record<string, Omit<Target, 'name'>> }
  return Object.entries(parsed.targets).map(([name, t]) => ({ name, ...t }))
}

function buildOrchestrator(depth: ScanDepth = 'full'): FractaOrchestrator {
  const o = new FractaOrchestrator({ depth, failOn: ['critical', 'high'], verbose: false, store, enricher })
  o.registerAgents([
    new HeadersAgent(), new AuthAgent(), new IdorAgent(),
    new DocsAgent(), new TenantAgent(), new RaceAgent(),
    new StripeAgent(), new DependenciesAgent(),
    new SecretsAgent(), new StackAgent(), new InfraAgent(), new ComplianceAgent(),
    new NestJSSkill(), new PrismaSkill(), new SupabaseSkill(),
  ])
  return o
}

/** Orchestrator SÓ dos agentes de repositório (SAST) — para `scan_repo` sem targets.yaml. */
function buildSastOrchestrator(repoPath: string): FractaOrchestrator {
  const healthCheck = async (): Promise<TargetHealth> => {
    const ok = existsSync(repoPath)
    return { repoAccessible: ok, status: ok ? 'healthy' : 'unreachable' }
  }
  const o = new FractaOrchestrator({ depth: 'full', failOn: ['critical', 'high'], verbose: false, store, enricher, healthCheck })
  o.registerAgents([
    new DependenciesAgent(), new SecretsAgent(), new StackAgent(),
    new ComplianceAgent(), new DocsAgent(),
  ])
  return o
}

const lastReports = new Map<string, ScanReport>()

const server = new Server(
  { name: 'fracta', version: '0.1.0' },
  { capabilities: { tools: {} } }
)

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'passive_scan',
      description:
        'Scan PASSIVO de qualquer URL, SEM config (headers, TLS, cookies, LGPD-lite: lê a política e detecta bot-management). Zero intrusão — seguro para qualquer site. Retorna nota A–F na hora.',
      inputSchema: {
        type: 'object',
        properties: { url: { type: 'string', description: 'URL a analisar (ex.: https://exemplo.com.br)' } },
        required: ['url'],
      },
    },
    {
      name: 'scan_repo',
      description:
        'Auditoria SAST do REPOSITÓRIO local, SEM config (dependências, secrets, SAST stack-aware, LGPD/compliance, docs). Read-only. Ideal para auditar o projeto que você está desenvolvendo, na IDE.',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Caminho do repositório (default: diretório atual)' },
          stack: { type: 'array', items: { type: 'string' }, description: 'Stack p/ checks dedicados (ex.: ["nestjs","prisma"]). Opcional.' },
        },
      },
    },
    {
      name: 'scan_target',
      description: 'Executa scan completo de segurança em um target configurado no targets.yaml',
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Nome do target (ex: doutor-inss)' },
          depth: { type: 'string', enum: ['quick', 'full', 'paranoid'], description: 'Profundidade do scan' },
        },
        required: ['target'],
      },
    },
    {
      name: 'test_auth',
      description: 'Testa autenticação: JWT alg:none, brute force, tokens malformados',
      inputSchema: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'] },
    },
    {
      name: 'test_idor',
      description: 'Testa IDOR e acesso cruzado entre IDs/tenants',
      inputSchema: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'] },
    },
    {
      name: 'check_headers',
      description: 'Verifica security headers e configuração de CORS',
      inputSchema: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'] },
    },
    {
      name: 'audit_docs',
      description: 'Audita arquivos .md do repositório',
      inputSchema: {
        type: 'object',
        properties: { repoPath: { type: 'string', description: 'Caminho do repositório (default: ./)' } },
      },
    },
    {
      name: 'get_findings',
      description: 'Retorna findings do último scan filtrados por severidade',
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        },
      },
    },
    {
      name: 'generate_report',
      description: 'Gera relatório do último scan em markdown ou JSON',
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string' },
          format: { type: 'string', enum: ['markdown', 'json'], default: 'markdown' },
        },
        required: ['target'],
      },
    },
  ],
}))

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params
  const a = (args ?? {}) as Record<string, string>

  try {
    // ── Zero-config: scan passivo de qualquer URL (reusa o motor do fracta.pro) ──
    if (name === 'passive_scan') {
      const url = a.url
      if (!url) return { content: [{ type: 'text', text: 'Informe `url`.' }] }
      const r = await new PassiveScanner().scan(url)
      const head = r.verdict === 'inconclusive'
        ? 'INCONCLUSIVO (alvo não avaliável — ausência de achados ≠ seguro)'
        : `Nota ${r.grade} (${r.score}/100)`
      const bySev = r.findings.reduce<Record<string, number>>((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {})
      const lines = r.findings.map(f => `- [${f.severity}] ${f.title}`)
      const txt = `Scan passivo de ${r.url}\n${head} · checks: ${r.checks.map(c => `${c.name}=${c.status}`).join(', ')}\nSeveridades: ${JSON.stringify(bySev)}\n\n${lines.join('\n') || '(sem achados nos checks executados)'}`
      return { content: [{ type: 'text', text: txt }] }
    }

    // ── Zero-config: auditoria SAST do repositório local (sem targets.yaml) ──
    if (name === 'scan_repo') {
      const path = (a.path && a.path.trim()) || process.cwd()
      if (!existsSync(path)) return { content: [{ type: 'text', text: `Caminho não encontrado: ${path}` }] }
      const rawStack = (args as Record<string, unknown> | undefined)?.stack
      const stack = Array.isArray(rawStack) ? rawStack.map(String) : []
      const target: Target = { name: 'repo-scan', url: 'file://local', stack, repoPath: path }
      const report = await buildSastOrchestrator(path).scan(target)
      lastReports.set('repo-scan', report)
      const { mdPath } = await new FractaReporter().save(report)
      const statusTxt = report.verdict === 'inconclusive' ? 'INCONCLUSIVO' : report.passed ? 'PASSOU' : 'FALHOU'
      const lines = report.findings.slice(0, 40).map(f => `- [${f.severity}] ${f.title}`)
      const more = report.findings.length > 40 ? `\n… +${report.findings.length - 40} achados` : ''
      const txt = `Auditoria SAST de ${path}\n${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium, ${report.summary.low} low. Status: ${statusTxt}.\nRelatório: ${mdPath}\n\n${lines.join('\n')}${more}`
      return { content: [{ type: 'text', text: txt }] }
    }

    if (name === 'scan_target' || name === 'test_auth' || name === 'test_idor' || name === 'check_headers') {
      const targets = await loadTargets()
      const target = targets.find(t => t.name === a.target)
      if (!target) return { content: [{ type: 'text', text: `Target "${a.target}" não encontrado no targets.yaml` }] }

      let agentFilter: string[] | undefined
      if (name === 'test_auth') agentFilter = ['AUTH Agent']
      else if (name === 'test_idor') agentFilter = ['IDOR Agent']
      else if (name === 'check_headers') agentFilter = ['HEADERS Agent']

      const scopedTarget = agentFilter ? { ...target, agents: agentFilter } : target
      const depth = (a.depth as ScanDepth) ?? 'full'
      const report = await buildOrchestrator(depth).scan(scopedTarget)
      lastReports.set(a.target, report)

      const reporter = new FractaReporter()
      const { mdPath } = await reporter.save(report)

      const statusTxt = report.verdict === 'inconclusive'
        ? 'INCONCLUSIVO (alvo não exercido — ausência de achados ≠ seguro)'
        : report.passed ? 'PASSOU' : 'FALHOU'
      const summary = `Scan concluído: ${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium. Status: ${statusTxt}. Relatório: ${mdPath}`
      return { content: [{ type: 'text', text: summary }] }
    }

    if (name === 'audit_docs') {
      const repoPath = a.repoPath ?? './'
      const docsTarget: Target = { name: 'docs-audit', url: 'file://local', stack: [] }
      const o = new FractaOrchestrator({ depth: 'full' })
      o.registerAgents([new DocsAgent(repoPath)])
      const report = await o.scan(docsTarget)
      lastReports.set('docs-audit', report)
      return { content: [{ type: 'text', text: `Docs audit: ${report.summary.total} findings. Medium: ${report.summary.medium}, Low: ${report.summary.low}` }] }
    }

    if (name === 'get_findings') {
      const report = lastReports.get(a.target ?? 'docs-audit')
      if (!report) return { content: [{ type: 'text', text: 'Nenhum scan encontrado. Execute scan_target primeiro.' }] }
      const findings = a.severity ? report.findings.filter(f => f.severity === a.severity) : report.findings
      return { content: [{ type: 'text', text: JSON.stringify(findings, null, 2) }] }
    }

    if (name === 'generate_report') {
      const report = lastReports.get(a.target)
      if (!report) return { content: [{ type: 'text', text: 'Nenhum scan encontrado. Execute scan_target primeiro.' }] }
      const reporter = new FractaReporter()
      const { mdPath, jsonPath } = await reporter.save(report)
      const path = a.format === 'json' ? jsonPath : mdPath
      return { content: [{ type: 'text', text: `Relatório salvo em: ${path}` }] }
    }

    return { content: [{ type: 'text', text: `Tool desconhecida: ${name}` }] }
  } catch (err) {
    return { content: [{ type: 'text', text: `Erro: ${String(err)}` }] }
  }
})

const transport = new StdioServerTransport()
await server.connect(transport)
