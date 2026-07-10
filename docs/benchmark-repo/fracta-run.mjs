// Roda o pipeline scan_repo do Fracta (dist buildado) num repoPath e imprime {findings:[...]}.
// Importa o dist COMPILADO por caminho relativo (funciona no layout do monorepo, sem symlinks).
// Requer `pnpm build` antes. Espelha buildSastOrchestrator() do mcp-server.
import { existsSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
// pathToFileURL: no Windows, import() exige file:// (não aceita 'C:\...' cru).
const d = (p) => pathToFileURL(join(root, 'packages', p, 'dist', 'index.js')).href

const { FractaOrchestrator } = await import(d('core'))
const { DependenciesAgent } = await import(d('agents/dependencies'))
const { SecretsAgent } = await import(d('agents/secrets'))
const { StackAgent } = await import(d('agents/stack'))
const { SemgrepAgent } = await import(d('agents/semgrep'))
const { ComplianceAgent } = await import(d('agents/compliance'))
const { DocsAgent } = await import(d('agents/docs'))

const repoPath = process.argv[2]
if (!repoPath) { console.error('uso: node fracta-run.mjs <repoPath>'); process.exit(1) }

const healthCheck = async () => ({ repoAccessible: existsSync(repoPath), status: existsSync(repoPath) ? 'healthy' : 'unreachable' })
const o = new FractaOrchestrator({ depth: 'full', failOn: ['critical', 'high'], verbose: false, healthCheck })
o.registerAgents([
  new DependenciesAgent(), new SecretsAgent(), new StackAgent(),
  new SemgrepAgent(), new ComplianceAgent(), new DocsAgent(),
])
// O orchestrator imprime um resumo humano em stdout — silencia durante o scan para
// que só o JSON saia (stdout limpo p/ o score.mjs consumir).
const realLog = console.log, realErr = console.error
console.log = () => {}; console.error = () => {}
const report = await o.scan({ name: 'bench', url: 'file://local', stack: ['nextjs', 'prisma'], repoPath })
console.log = realLog; console.error = realErr
console.log(JSON.stringify({ findings: report.findings ?? [] }))
