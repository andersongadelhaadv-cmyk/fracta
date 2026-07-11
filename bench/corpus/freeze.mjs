#!/usr/bin/env node
// Fase 1 (verificador) — confere que cada SHA congelado ainda RESOLVE e que o treeSha bate.
// É o guardião da reprodutibilidade: detecta repo que sumiu (deletado/privado → force-push do SHA)
// ANTES da rodada cara. Não altera a seleção; só anota o estado de cada âncora.
//
//   node freeze.mjs            # verifica todos
//   node freeze.mjs --limit 5
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { parse as parseYaml } from 'yaml'

const HERE = dirname(fileURLToPath(import.meta.url))
const argv = process.argv.slice(2)
const flag = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 ? argv[i + 1] : d }
const LIMIT = flag('limit') ? Number(flag('limit')) : Infinity
const MANIFEST = join(HERE, 'manifest.yaml')

function ghTreeSha(owner, name, sha) {
  try {
    const c = JSON.parse(execFileSync('gh', ['api', `repos/${owner}/${name}/commits/${sha}`], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }))
    return { ok: true, treeSha: c.commit?.tree?.sha ?? null }
  } catch (e) {
    return { ok: false, err: (e.stderr || e.message || '').toString().slice(0, 160) }
  }
}

function main() {
  if (!existsSync(MANIFEST)) { console.error('manifest ausente — rode build-manifest.mjs'); process.exit(1) }
  const m = parseYaml(readFileSync(MANIFEST, 'utf8'))
  const repos = (m.repos || []).slice(0, LIMIT)
  let ok = 0, drift = 0, vanished = 0
  const report = []
  for (const r of repos) {
    const v = ghTreeSha(r.owner, r.name, r.sha)
    if (!v.ok) { vanished++; report.push({ id: `${r.owner}/${r.name}`, state: 'vanished', err: v.err }); continue }
    if (r.treeSha && v.treeSha && v.treeSha !== r.treeSha) { drift++; report.push({ id: `${r.owner}/${r.name}`, state: 'drift', expected: r.treeSha, got: v.treeSha }); continue }
    ok++
  }
  const summary = { checkedAt: new Date().toISOString(), total: repos.length, ok, drift, vanished, report: report.slice(0, 50) }
  writeFileSync(join(HERE, 'freeze-report.json'), JSON.stringify(summary, null, 2))
  console.log(`Freeze: ${ok} ok · ${drift} drift · ${vanished} vanished (de ${repos.length})`)
  if (drift || vanished) console.log('Detalhe em bench/corpus/freeze-report.json (viram robustez no relatório)')
}

main()
