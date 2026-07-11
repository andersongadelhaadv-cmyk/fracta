#!/usr/bin/env node
// Runner de batch (Fase 2): clona cada repo do manifest --depth 1 no SHA congelado, roda o
// scan_repo do Fracta (via scan-one.mjs em processo filho), grava raw.json redigido e classifica
// o desfecho (ok/timeout/crash/oom). Idempotente e RETOMÁVEL: se cair no repo 237, retoma do 237.
//
//   node run-batch.mjs                 # lê bench/corpus/manifest.yaml, clona e escaneia
//   node run-batch.mjs --fixtures      # escaneia bench/fixtures/repos/* (sem clone, stratum=fixture)
//   node run-batch.mjs --limit 12      # piloto: só os N primeiros
//   flags: --concurrency N (4) · --timeout-ms N (600000) · --out DIR (bench/results)
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync, appendFileSync, rmSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { parse as parseYaml } from 'yaml'
import { classifyOutcome } from './outcome.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..', '..')
const BENCH = join(ROOT, 'bench')

// ---- args ----
const argv = process.argv.slice(2)
const flag = (name, def) => { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : def }
const has = (name) => argv.includes('--' + name)
const CONCURRENCY = Number(flag('concurrency', 4))
const TIMEOUT_MS = Number(flag('timeout-ms', 600_000))
const RETRY = 1
const OUT = flag('out', join(BENCH, 'results'))
const LIMIT = flag('limit') ? Number(flag('limit')) : Infinity
const FIXTURES = has('fixtures')
const KEEP_CLONES = has('keep-clones')
const STRATUM = flag('stratum') // filtra o manifest por estrato (p/ shards do CI)

const idOf = (owner, name) => `${owner}__${name}`.replace(/[^\w.-]/g, '-')

// ---- alvos ----
function targets() {
  if (FIXTURES) {
    const base = join(BENCH, 'fixtures', 'repos')
    if (!existsSync(base)) { console.error('fixtures ausentes — rode: node bench/fixtures/generate.mjs'); process.exit(1) }
    return readdirSync(base).filter((d) => statSync(join(base, d)).isDirectory())
      .map((d) => ({ id: d, stratum: 'fixture', localPath: join(base, d) }))
  }
  const mf = join(BENCH, 'corpus', 'manifest.yaml')
  if (!existsSync(mf)) { console.error('manifest ausente — rode: node bench/corpus/build-manifest.mjs'); process.exit(1) }
  const m = parseYaml(readFileSync(mf, 'utf8'))
  return (m.repos || [])
    .filter((r) => !STRATUM || r.stratum === STRATUM)
    .map((r) => ({ id: idOf(r.owner, r.name), owner: r.owner, name: r.name, url: r.url || `https://github.com/${r.owner}/${r.name}.git`, sha: r.sha, stratum: r.stratum }))
}

// ---- clone --depth 1 @SHA (idempotente) ----
function run(cmd, args, opts = {}) {
  return new Promise((res) => {
    const p = spawn(cmd, args, { ...opts, shell: false })
    let out = '', err = ''
    p.stdout?.on('data', (d) => (out += d)); p.stderr?.on('data', (d) => (err += d))
    p.on('error', (e) => res({ code: -1, out, err: err + e.message }))
    p.on('close', (code) => res({ code, out, err }))
  })
}
async function cloneAtSha(t, dir) {
  rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true })
  let r = await run('git', ['init', '-q'], { cwd: dir })
  if (r.code !== 0) return { ok: false, err: 'git init: ' + r.err }
  await run('git', ['remote', 'add', 'origin', t.url], { cwd: dir })
  // fetch do SHA exato a --depth 1 (GitHub permite want-sha) → congelamento reprodutível
  r = await run('git', ['fetch', '--depth', '1', 'origin', t.sha], { cwd: dir })
  if (r.code !== 0) return { ok: false, err: 'git fetch: ' + r.err.slice(0, 300) }
  r = await run('git', ['checkout', '-q', 'FETCH_HEAD'], { cwd: dir })
  if (r.code !== 0) return { ok: false, err: 'git checkout: ' + r.err.slice(0, 300) }
  return { ok: true }
}

// ---- scan via processo filho, com timeout de verdade ----
function scanChild(repoPath) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [join(HERE, 'scan-one.mjs'), repoPath], { shell: false })
    let out = '', err = '', timedOut = false
    const timer = setTimeout(() => { timedOut = true; p.kill('SIGKILL') }, TIMEOUT_MS)
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d))
    p.on('close', (code) => {
      clearTimeout(timer)
      if (timedOut) return resolve({ timedOut: true, error: 'timeout' })
      if (code !== 0) return resolve({ error: err.trim() || `exit ${code}` })
      try { resolve({ report: JSON.parse(out) }) } catch (e) { resolve({ error: 'bad JSON: ' + e.message + ' :: ' + err.slice(0, 200) }) }
    })
  })
}

// ---- summary redigido (metadata-only; SEM texto-livre → seguro p/ commit) ----
function summaryRecord(t, outcome, res) {
  const rep = res.report
  const findings = (rep?.findings || []).map((f) => ({
    id: f.id, category: f.category, camada: f.camada, severity: f.severity,
    confidence: f.confidence, agent: f.agent,
    file: f.location?.file, line: f.location?.line,
  }))
  const checks = (rep?.checks || []).map((c) => ({ agent: c.agent, status: c.status, degraded: c.degraded }))
  return {
    id: t.id, stratum: t.stratum, sha: t.sha || null, outcome,
    durationMs: rep?.durationMs ?? null, verdict: rep?.verdict ?? null,
    summary: rep?.summary ?? null, findings, checks,
  }
}

async function processOne(t) {
  const outDir = join(OUT, t.id)
  const rawPath = join(outDir, 'raw.json')
  const outcomePath = join(outDir, 'outcome.json')
  // Retomável: pula o que já teve um desfecho registrado (tentado-uma-vez). Para reprocessar
  // um repo, apague results/<id>/ ou rode com results/ limpo.
  if (existsSync(outcomePath)) return { id: t.id, outcome: 'cached', skipped: true }
  mkdirSync(outDir, { recursive: true })

  let repoPath = t.localPath
  if (!repoPath) {
    const cloneDir = join(OUT, '_clones', t.id)
    const cl = await cloneAtSha(t, cloneDir)
    if (!cl.ok) {
      const rec = { id: t.id, stratum: t.stratum, sha: t.sha, outcome: 'vanished', error: cl.err }
      writeFileSync(join(outDir, 'outcome.json'), JSON.stringify(rec, null, 2))
      return rec
    }
    repoPath = cloneDir
  }

  let res, outcome
  for (let attempt = 1; attempt <= RETRY + 1; attempt++) {
    res = await scanChild(repoPath)
    outcome = classifyOutcome(res)
    if (outcome === 'ok' || outcome === 'timeout' || outcome === 'oom') break // só re-tenta crash
    if (attempt <= RETRY) continue
  }

  writeFileSync(rawPath, JSON.stringify(res.report ?? { error: res.error }, null, 0))
  const sr = summaryRecord(t, outcome, res)
  writeFileSync(join(outDir, 'outcome.json'), JSON.stringify({ id: t.id, outcome, durationMs: res.report?.durationMs, error: res.error }, null, 2))
  appendFileSync(join(OUT, 'summary.jsonl'), JSON.stringify(sr) + '\n')

  // limpa o clone (não deixa 400 repos em disco) — salvo --keep-clones (p/ o crosscheck usar o MESMO SHA)
  if (!t.localPath && !KEEP_CLONES) rmSync(join(OUT, '_clones', t.id), { recursive: true, force: true })
  return { id: t.id, outcome }
}

// ---- pool de concorrência ----
async function pool(items, n, fn) {
  const results = []; let i = 0
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const idx = i++; results[idx] = await fn(items[idx], idx) }
  })
  await Promise.all(workers)
  return results
}

async function main() {
  mkdirSync(OUT, { recursive: true })
  const all = targets().slice(0, LIMIT)
  console.log(`Batch: ${all.length} alvos · concorrência ${CONCURRENCY} · timeout ${TIMEOUT_MS / 1000}s · out ${OUT}`)
  // reseta summary.jsonl só se recomeçando do zero (nenhum raw ainda)
  const anyDone = all.some((t) => existsSync(join(OUT, t.id, 'raw.json')))
  if (!anyDone) writeFileSync(join(OUT, 'summary.jsonl'), '')

  const tally = {}
  let done = 0
  await pool(all, CONCURRENCY, async (t) => {
    const r = await processOne(t)
    tally[r.outcome] = (tally[r.outcome] || 0) + 1
    done++
    if (done % 10 === 0 || done === all.length) console.log(`  ${done}/${all.length} · ${JSON.stringify(tally)}`)
    return r
  })
  console.log('Desfechos:', JSON.stringify(tally))
  console.log('Summary redigido:', join(OUT, 'summary.jsonl'))
}

if (process.argv[1]?.endsWith('run-batch.mjs')) main().catch((e) => { console.error(e); process.exit(1) })
