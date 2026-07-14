#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { scanFleet, diffAgainstBaseline, ratchetBaseline, type Baseline } from './monitor.js'
import { buildReport } from './report.js'

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(name)
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback
}

function loadBaseline(path: string): Baseline {
  if (!existsSync(path)) return {}
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Baseline
  } catch {
    return {}
  }
}

async function main(): Promise<void> {
  const baselinePath = arg('--baseline', 'fleet-baseline.json')
  const outDir = arg('--out', '.')

  const baseline = loadBaseline(baselinePath)
  console.log(`[monitor] scaneando a frota (baseline: ${Object.keys(baseline).length} alvos conhecidos)…`)

  const results = await scanFleet()
  const regressions = diffAgainstBaseline(results, baseline)
  const when = new Date().toISOString()

  // Baseline com CATRACA: o alvo que regrediu MANTÉM o último estado bom, então a
  // regressão segue sendo detectada a cada run até alguém consertar. Antes o baseline
  // era sobrescrito com o estado atual — a queda virava o novo "normal" no dia seguinte
  // e o alarme morria (a frota ficou 7/16 degradada em silêncio). Ver ratchetBaseline().
  writeFileSync(baselinePath, JSON.stringify(ratchetBaseline(results, baseline), null, 2) + '\n')
  writeFileSync(join(outDir, 'fleet-report.md'), buildReport(results, regressions, when))
  writeFileSync(join(outDir, 'regressions.json'), JSON.stringify(regressions, null, 2) + '\n')

  for (const r of results) {
    const g = r.verdict === 'inconclusive' ? 'inconclusivo' : (r.grade ?? '—')
    console.log(`  ${r.label.padEnd(20)} ${r.domain.padEnd(26)} ${g}`)
  }
  if (regressions.length) {
    console.log(`\n[monitor] ⚠️ ${regressions.length} regressão(ões):`)
    for (const g of regressions) console.log(`  - ${g.label} (${g.domain}): ${g.kind} ${g.before} → ${g.after}`)
  } else {
    console.log('\n[monitor] ✅ sem regressões')
  }
  // Sempre exit 0: o workflow lê regressions.json p/ decidir abrir issue.
}

main().catch((e) => {
  console.error('[monitor] erro fatal:', e)
  process.exit(1)
})
