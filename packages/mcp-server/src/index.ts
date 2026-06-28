import { readFile } from 'fs/promises'
import { parse as parseYaml } from 'yaml'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { FractaOrchestrator } from '@fracta/core'
import type { Target, ScanReport, ScanDepth } from '@fracta/core'
import { AuthAgent } from '@fracta/agent-auth'
import { HeadersAgent } from '@fracta/agent-headers'
import { IdorAgent } from '@fracta/agent-idor'
import { DocsAgent } from '@fracta/agent-docs'
import { TenantAgent } from '@fracta/agent-tenant'
import { RaceAgent } from '@fracta/agent-race'
import { StripeAgent } from '@fracta/agent-stripe'
import { NestJSSkill } from '@fracta/skill-nestjs'
import { PrismaSkill } from '@fracta/skill-prisma'
import { SupabaseSkill } from '@fracta/skill-supabase'
import { FractaReporter } from '@fracta/reporter'
import { SqliteFindingStore } from '@fracta/store'

const TARGETS_CONFIG = process.env.TARGETS_CONFIG ?? './configs/targets.yaml'

// Estado entre execuções compartilhado por toda a sessão MCP (stdio = processo longo).
const store = new SqliteFindingStore(process.env.FRACTA_STATE ?? './fracta-state.db')

async function loadTargets(): Promise<Target[]> {
  const raw = await readFile(TARGETS_CONFIG, 'utf-8')
  const resolved = raw.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] ?? '')
  const parsed = parseYaml(resolved) as { targets: Record<string, Omit<Target, 'name'>> }
  return Object.entries(parsed.targets).map(([name, t]) => ({ name, ...t }))
}

function buildOrchestrator(depth: ScanDepth = 'full'): FractaOrchestrator {
  const o = new FractaOrchestrator({ depth, failOn: ['critical', 'high'], verbose: false, store })
  o.registerAgents([
    new HeadersAgent(), new AuthAgent(), new IdorAgent(),
    new DocsAgent(), new TenantAgent(), new RaceAgent(),
    new StripeAgent(),
    new NestJSSkill(), new PrismaSkill(), new SupabaseSkill(),
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

      const summary = `Scan concluído: ${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium. Status: ${report.passed ? 'PASSOU' : 'FALHOU'}. Relatório: ${mdPath}`
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
