// Roda o pipeline scan_repo do Fracta (dist buildado) num repoPath e imprime, em stdout,
// UM json redigido: { durationMs, summary, verdict, passed, checks[], findings[] }.
// Espelha buildSastOrchestrator() do mcp-server (mesma escolha de fracta-run.mjs), mas captura
// TAMBÉM o status por-check (ok/skipped/error) — a camada de honestidade — e REDIGE segredos.
//
// Projetado para ser spawnado como PROCESSO FILHO por run-batch.mjs → timeout/crash/oom
// isolados de verdade, e o patch global de console.log não vaza entre scans concorrentes.
//
//   node scan-one.mjs <repoPath>
import { existsSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'
import { redactFinding, redactSecrets } from './redact.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const d = (p) => pathToFileURL(join(root, 'packages', p, 'dist', 'index.js')).href

export async function scanRepo(repoPath, { stack = ['nextjs', 'prisma'] } = {}) {
  const { FractaOrchestrator } = await import(d('core'))
  const { DependenciesAgent } = await import(d('agents/dependencies'))
  const { SecretsAgent } = await import(d('agents/secrets'))
  const { StackAgent } = await import(d('agents/stack'))
  const { SemgrepAgent } = await import(d('agents/semgrep'))
  const { ComplianceAgent } = await import(d('agents/compliance'))
  const { DocsAgent } = await import(d('agents/docs'))

  const healthCheck = async () => ({ repoAccessible: existsSync(repoPath), status: existsSync(repoPath) ? 'healthy' : 'unreachable' })
  const o = new FractaOrchestrator({ depth: 'full', failOn: ['critical', 'high'], verbose: false, healthCheck })
  o.registerAgents([
    new DependenciesAgent(), new SecretsAgent(), new StackAgent(),
    new SemgrepAgent(), new ComplianceAgent(), new DocsAgent(),
  ])

  // O orchestrator imprime resumo humano em stdout — silencia p/ manter o stdout = só o JSON.
  const realLog = console.log, realErr = console.error
  console.log = () => {}; console.error = () => {}
  const t0 = Date.now()
  let report
  try {
    report = await o.scan({ name: 'bench', url: 'file://local', stack, repoPath })
  } finally {
    console.log = realLog; console.error = realErr
  }
  const durationMs = Date.now() - t0

  // checks: mantém o status/motivo (honestidade), descarta os findings embutidos (já vão no topo),
  // e redige o motivo por precaução.
  const checks = (report.checks || []).map((c) => ({
    agent: c.agent, camada: c.camada, status: c.status,
    motivo: redactSecrets(c.motivo), degraded: !!c.degraded,
    durationMs: c.durationMs, findingCount: (c.findings || []).length,
  }))
  const findings = (report.findings || []).map(redactFinding)

  return {
    durationMs,
    summary: report.summary,
    verdict: report.verdict,
    passed: report.passed,
    checks,
    findings,
  }
}

if (process.argv[1]?.endsWith('scan-one.mjs')) {
  const repoPath = process.argv[2]
  if (!repoPath) { process.stderr.write('uso: node scan-one.mjs <repoPath>\n'); process.exit(2) }
  scanRepo(repoPath).then((r) => {
    // Alguns agentes deixam handles abertos (keep-alive de fetch, stdio de subprocesso) →
    // o node não sai sozinho. Força a saída DEPOIS do flush do stdout (senão o JSON trunca).
    process.stdout.write(JSON.stringify(r), () => process.exit(0))
  }).catch((e) => {
    process.stderr.write('SCAN_ERROR: ' + (e?.stack || e?.message || String(e)) + '\n')
    process.exit(1)
  })
}
