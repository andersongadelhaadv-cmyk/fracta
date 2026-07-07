#!/usr/bin/env node
import { readFile, writeFile, access, mkdir } from 'fs/promises'
import { dirname } from 'path'
import { parseArgs } from 'util'
import { parse as parseYaml } from 'yaml'
import { FractaOrchestrator, assertUsableTarget } from '@fracta/core'
import type { Target, ScanDepth, Severity } from '@fracta/core'
import { AuthAgent } from '@fracta/agent-auth'
import { HeadersAgent } from '@fracta/agent-headers'
import { DnsAgent } from '@fracta/agent-dns'
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
import pkg from '../package.json' with { type: 'json' }

const BANNER = `
███████╗██████╗  █████╗  ██████╗████████╗ █████╗
██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔══██╗
█████╗  ██████╔╝███████║██║        ██║   ███████║
██╔══╝  ██╔══██╗██╔══██║██║        ██║   ██╔══██║
██║     ██║  ██║██║  ██║╚██████╗   ██║   ██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝

The Complete SaaS Audit Framework — v${pkg.version}
`

interface TargetsFile {
  targets: Record<string, Omit<Target, 'name'>>
}

async function loadTargets(configPath: string): Promise<Target[]> {
  const raw = await readFile(configPath, 'utf-8')
  const resolved = raw.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] ?? '')
  const parsed = parseYaml(resolved) as TargetsFile
  const targets = Object.entries(parsed.targets).map(([name, t]) => ({ name, ...t }))
  // Erra cedo com mensagem clara se um target estiver inutilizável (ex.: `baseUrl:`
  // trocado por `url:`) — nunca deixa virar crash cru + veredito verde enganoso (#26).
  for (const t of targets) assertUsableTarget(t)
  return targets
}

async function main(): Promise<void> {
  console.log(BANNER)

  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      target: { type: 'string', short: 't' },
      config: { type: 'string', short: 'c', default: './configs/targets.yaml' },
      depth: { type: 'string', short: 'd', default: 'full' },
      output: { type: 'string', short: 'o', default: './fracta-reports' },
      state: { type: 'string', default: './fracta-state.db' },
      'no-state': { type: 'boolean', default: false },
      llm: { type: 'boolean', default: false },
      'no-llm': { type: 'boolean', default: false },
      'fail-on': { type: 'string', default: 'critical,high' },
      'docs-path': { type: 'string', default: './' },
      force: { type: 'boolean', default: false },
      verbose: { type: 'boolean', short: 'v', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  const command = positionals[0] ?? 'scan'

  const VALID_COMMANDS = ['scan', 'docs', 'verify', 'init', 'help'] as const
  type ValidCommand = typeof VALID_COMMANDS[number]

  if (!VALID_COMMANDS.includes(command as ValidCommand)) {
    console.error(`[Fracta] Unknown command: "${command}"`)
    console.error(`         Valid commands: ${VALID_COMMANDS.join(', ')}`)
    console.error(`         Run "fracta --help" for usage.`)
    process.exit(1)
  }

  if (values.help || command === 'help') {
    console.log(`
Usage: fracta <command> [options]

Commands:
  scan          Run full security scan (default)
  docs          Run documentation audit only
  verify <url>  Verificação em runtime (browser) de consentimento/trackers.
  init [path]   Cria um targets.yaml inicial comentado (default: ./configs/targets.yaml).

Options:
  -t, --target      Target name from targets.yaml (default: all)
  -c, --config      Path to targets.yaml (default: ./configs/targets.yaml)
  -d, --depth       Scan depth: quick | full | paranoid (default: full)
  -o, --output      Output directory (default: ./fracta-reports)
  --state           SQLite state file for regression/suppression (default: ./fracta-state.db)
  --no-state        Disable cross-run state (no regression/suppression)
  --llm             OPT-IN: enable the LLM edge (prioritization/fix drafting).
                    CONSOME TOKENS. Default OFF → zero tokens. Requires ANTHROPIC_API_KEY.
                    Modelo via FRACTA_LLM_MODEL (default claude-opus-4-8; use um mais barato p/ economizar).
  --no-llm          (redundante; LLM já é off por padrão) força o LLM desligado
  --fail-on         Severities that cause exit(1) (default: critical,high)
  --docs-path       Repo path for the dedicated 'docs' command (default: ./).
                    In 'scan', DOCS uses the target's repoPath and skips if absent.
  --force           (init) sobrescreve um targets.yaml existente
  -v, --verbose     Verbose output
  -h, --help        Show this help
`)
    process.exit(0)
  }

  if (command === 'init') {
    const { runInit } = await import('./init.js')
    const path = positionals[1] ?? (values.config as string)
    const result = await runInit(
      { path, force: values.force as boolean },
      {
        exists: async (p) => { try { await access(p); return true } catch { return false } },
        write: async (p, content) => { await mkdir(dirname(p), { recursive: true }); await writeFile(p, content, 'utf-8') },
      },
    )
    console.log(result.message)
    process.exit(result.ok ? 0 : 1)
  }

  if (command === 'verify') {
    const targetUrl = positionals[1]
    if (!targetUrl) {
      console.error('[Fracta] Uso: fractascan verify <url>')
      process.exit(2)
    }
    try {
      const { RuntimeVerifier } = await import('@fracta/verify')
      const report = await new RuntimeVerifier().verifyConsent(targetUrl)
      console.log(`Verificação em runtime de ${report.url}`)
      console.log(report.evidence.firedBeforeInteraction
        ? `⚠️  trackers dispararam ANTES do consentimento: ${report.evidence.trackers.map(t => t.name).join(', ')}`
        : '✅ nenhum tracker disparou antes do consentimento')
      console.log(`CMP: ${report.evidence.cmp.detected ? report.evidence.cmp.vendor : 'não detectado'}`)
      for (const f of report.findings) console.log(`- [${f.severity}] ${f.title}`)
      process.exit(0)
    } catch (e) {
      const err = e as Error
      console.error(err.name === 'BrowserUnavailableError'
        ? err.message
        : `[Fracta] Falha na verificação: ${err.message}`)
      process.exit(1)
    }
  }

  // Regra 1: o Fracta audita UM SaaS por vez. --target é obrigatório no scan —
  // nunca varrer todos os alvos de uma vez (blast radius contido a um produto).
  if (command === 'scan' && !values.target) {
    console.error('[Fracta] --target é obrigatório: o Fracta audita UM SaaS por vez (blast radius contido).')
    console.error('         Ex: fracta scan --target doutor-inss')
    process.exit(1)
  }

  let targets: Target[]
  try {
    targets = await loadTargets(values.config as string)
  } catch (err) {
    console.error(`[Fracta] Error reading config: ${values.config}\n${String(err)}`)
    process.exit(1)
  }

  if (values.target) {
    targets = targets.filter(t => t.name === values.target)
    if (targets.length === 0) {
      console.error(`[Fracta] Target "${values.target}" not found in ${values.config}`)
      process.exit(1)
    }
  }

  const VALID_DEPTHS: ScanDepth[] = ['quick', 'full', 'paranoid']
  const depthArg = values.depth as string
  if (!VALID_DEPTHS.includes(depthArg as ScanDepth)) {
    console.error(`[Fracta] Invalid --depth value: "${depthArg}"`)
    console.error(`         Valid values: ${VALID_DEPTHS.join(', ')}`)
    process.exit(1)
  }
  const depth = depthArg as ScanDepth
  const failOn = (values['fail-on'] as string).split(',').map(s => s.trim()) as Severity[]
  const docsPath = values['docs-path'] as string

  const allAgents = command === 'docs'
    ? [new DocsAgent(docsPath)]
    : [
        new HeadersAgent(),
        new DnsAgent(),
        new AuthAgent(),
        new IdorAgent(),
        // No scan, o DOCS Agent deriva o repo de `target.repoPath` e PULA se ausente
        // — nunca cai no cwd (escanearia o próprio Fracta). O override `--docs-path`
        // vale só para o comando dedicado `fracta docs`.
        new DocsAgent(),
        new TenantAgent(),
        new RaceAgent(),
        new StripeAgent(),
        new DependenciesAgent(),
        new SecretsAgent(),
        new StackAgent(),
        new InfraAgent(),
        new ComplianceAgent(),
        new NestJSSkill(),
        new PrismaSkill(),
        new SupabaseSkill(),
      ]

  // Estado entre runs é OPCIONAL. Se o store não puder ser criado (ex.: Node < 22.5
  // sem node:sqlite, ou fs read-only), degrada para "sem estado" — a detecção segue
  // intacta (regra Fase 2: falha de persistência nunca derruba a detecção).
  let store: SqliteFindingStore | undefined
  if (!values['no-state']) {
    try {
      store = new SqliteFindingStore(values.state as string)
    } catch (err) {
      console.warn(`[Fracta] Estado entre runs indisponível: ${(err as Error).message}`)
      console.warn(`[Fracta] Seguindo SEM regressão/supressão (detecção intacta). Use --no-state para silenciar.`)
    }
  }

  // Borda LLM: OPT-IN. Só liga com --llm (e exige ANTHROPIC_API_KEY). Default OFF →
  // ZERO tokens. `--no-llm` mantém compat (força off). A detecção nunca depende dela.
  const llmOn = (values.llm as boolean) && !(values['no-llm'] as boolean)
  if (values.llm && !process.env.ANTHROPIC_API_KEY) {
    console.warn('[Fracta] --llm pedido, mas ANTHROPIC_API_KEY ausente — seguindo SEM LLM (zero tokens).')
  }
  const enricher = llmOn ? new LlmEnricher({ verbose: values.verbose as boolean }) : undefined
  if (enricher) {
    console.log(`[Fracta] LLM enrichment LIGADO — CONSOME TOKENS (modelo: ${process.env.FRACTA_LLM_MODEL ?? 'claude-opus-4-8'}).`)
  }

  const orchestrator = new FractaOrchestrator({
    concurrency: 3,
    failOn,
    depth,
    verbose: values.verbose as boolean,
    store,
    enricher,
  })
  orchestrator.registerAgents(allAgents)

  const reporter = new FractaReporter({ outputDir: values.output as string, toolVersion: pkg.version })

  let anyFailed = false

  try {
    for (const target of targets) {
      const report = await orchestrator.scan(target)
      const { mdPath, jsonPath, sarifPath } = await reporter.save(report)
      console.log(`\n[Fracta] Reports saved:`)
      console.log(`  Markdown: ${mdPath}`)
      console.log(`  JSON:     ${jsonPath}`)
      console.log(`  SARIF:    ${sarifPath}  (upload no GitHub Code Scanning)`)
      if (report.resumo.regressoes > 0) {
        console.log(`  ⏪ Regressões detectadas: ${report.resumo.regressoes}`)
      }
      if (!report.passed) anyFailed = true
    }
  } finally {
    store?.close()
  }

  process.exit(anyFailed ? 1 : 0)
}

main().catch(err => {
  console.error('[Fracta] Fatal error:', err)
  process.exit(1)
})
