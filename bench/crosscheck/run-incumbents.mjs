#!/usr/bin/env node
// Fase 3c — roda gitleaks/semgrep/trivy nos MESMOS repos@SHA e grava a saída normalizada por
// categoria, p/ a tabela comparativa do relatório. NÃO é ground truth (duas ferramentas
// concordando podem ambas errar) — é concordância/discordância, a continuação do 15/18 de 10/07.
//
// Cada ferramenta ausente entra como "unavailable" (não como 0 — 0 mentiria). gitleaks e trivy
// caem para `docker run` se o binário não estiver no PATH.
//
//   node run-incumbents.mjs                 # sobre os clones do manifest (re-clona se preciso)
//   node run-incumbents.mjs --fixtures      # sobre bench/fixtures/repos/*
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const BENCH = join(HERE, '..')
const argv = process.argv.slice(2)
const FIXTURES = argv.includes('--fixtures')
const OUT = join(BENCH, 'results')

const have = (bin) => { try { execFileSync(bin, ['--version'], { stdio: 'ignore' }); return true } catch { return false } }
const haveDocker = have('docker')

function tryRun(bin, args, opts = {}) {
  const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts })
  return { code: r.status ?? -1, out: r.stdout || '', err: r.stderr || '' }
}

// --- gitleaks (segredos) ---
function gitleaks(repoPath) {
  if (have('gitleaks')) {
    const r = tryRun('gitleaks', ['detect', '--no-git', '-f', 'json', '-r', '/dev/stdout', '--source', repoPath])
    return { available: true, via: 'binary', count: parseCount(r.out, 'array') }
  }
  if (haveDocker) {
    const r = tryRun('docker', ['run', '--rm', '-v', `${repoPath}:/repo:ro`, 'zricethezav/gitleaks:latest', 'detect', '--no-git', '-f', 'json', '-r', '/dev/stdout', '--source', '/repo'])
    return { available: true, via: 'docker', count: parseCount(r.out, 'array') }
  }
  return { available: false }
}

// --- semgrep (SAST) ---
function semgrep(repoPath) {
  if (!have('semgrep')) return { available: false }
  const r = tryRun('semgrep', ['scan', '--config', 'p/security-audit', '--json', '--quiet', repoPath], { timeout: 180_000 })
  try { const j = JSON.parse(r.out); return { available: true, via: 'binary', count: (j.results || []).length } }
  catch { return { available: true, via: 'binary', count: null, note: 'timeout/parse' } }
}

// --- trivy (deps/CVE) ---
function trivy(repoPath) {
  if (have('trivy')) {
    const r = tryRun('trivy', ['fs', '--scanners', 'vuln', '-f', 'json', repoPath])
    return { available: true, via: 'binary', count: trivyCount(r.out) }
  }
  if (haveDocker) {
    const r = tryRun('docker', ['run', '--rm', '-v', `${repoPath}:/repo:ro`, 'aquasec/trivy:latest', 'fs', '--scanners', 'vuln', '-f', 'json', '/repo'])
    return { available: true, via: 'docker', count: trivyCount(r.out) }
  }
  return { available: false }
}

function parseCount(out, shape) { try { const j = JSON.parse(out); return Array.isArray(j) ? j.length : (j.results || []).length } catch { return null } }
function trivyCount(out) { try { const j = JSON.parse(out); let n = 0; for (const res of j.Results || []) n += (res.Vulnerabilities || []).length; return n } catch { return null } }

function targets() {
  if (FIXTURES) {
    const base = join(BENCH, 'fixtures', 'repos')
    return readdirSync(base).filter((d) => statSync(join(base, d)).isDirectory()).map((d) => ({ id: d, path: join(base, d) }))
  }
  const cl = join(OUT, '_clones')
  if (!existsSync(cl)) { console.error('sem clones — o crosscheck roda melhor logo após bench:run (que limpa clones). Use --fixtures ou preserve _clones.'); process.exit(1) }
  return readdirSync(cl).filter((d) => statSync(join(cl, d)).isDirectory()).map((d) => ({ id: d, path: join(cl, d) }))
}

function main() {
  console.log(`Crosscheck incumbentes · gitleaks:${have('gitleaks') ? 'bin' : haveDocker ? 'docker' : 'NA'} · semgrep:${have('semgrep') ? 'bin' : 'NA'} · trivy:${have('trivy') ? 'bin' : haveDocker ? 'docker' : 'NA'}`)
  const all = targets()
  const rows = []
  for (const t of all) {
    const gl = gitleaks(t.path), sg = semgrep(t.path), tv = trivy(t.path)
    rows.push({ id: t.id, gitleaks: gl, semgrep: sg, trivy: tv })
    console.log(`  ${t.id}: gitleaks=${fmt(gl)} semgrep=${fmt(sg)} trivy=${fmt(tv)}`)
  }
  mkdirSync(OUT, { recursive: true })
  writeFileSync(join(OUT, 'incumbents.json'), JSON.stringify({ generatedAt: new Date().toISOString(), rows }, null, 2))
  console.log('Gravado em', join(OUT, 'incumbents.json'))
}
const fmt = (r) => (r.available ? (r.count ?? '?') : 'NA')

main()
