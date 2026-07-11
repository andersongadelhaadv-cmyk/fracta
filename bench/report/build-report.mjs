#!/usr/bin/env node
// Fase 4 — gera o relatório a partir dos artefatos versionados/locais. Reproduz o NÚMERO a
// partir de results/summary.jsonl (redigido) — não re-clona nada. Separa o MEDIDO do PENDENTE.
//
// Entradas (todas opcionais exceto summary): summary.jsonl, fixtures/catalog.json + fixture raws,
// results/labels.csv, results/incumbents.json, corpus/freeze-report.json.
// Saídas: bench/report/report.md (versionado) + bench/report/report.json (p/ fracta.pro).
import { existsSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { wilson } from './stats.mjs'
import { matchCatalog } from './oracle.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const BENCH = join(HERE, '..')
const OUT = join(BENCH, 'results')
const readJson = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')) } catch { return null } }
const pct = (r) => (r.point == null ? '—' : `${(r.point * 100).toFixed(0)}%`)
const ci = (r) => (r.n === 0 ? 'sem dados' : `[${(r.low * 100).toFixed(0)}–${(r.high * 100).toFixed(0)}%] (n=${r.n})`)

// ---------- ROBUSTEZ + inventário de findings (de summary.jsonl) ----------
function loadSummary() {
  const p = join(OUT, 'summary.jsonl')
  if (!existsSync(p)) return { records: [] }
  const records = readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
  return { records }
}

// ---------- RECALL nos fixtures (matchCatalog contra o oráculo) ----------
function fixtureRecall() {
  const catalog = readJson(join(BENCH, 'fixtures', 'catalog.json'))
  if (!catalog) return null
  const byFixture = {}
  for (const it of catalog.items) (byFixture[it.fixture] ||= []).push(it)
  const perCat = {}
  const missed = []
  let skippedNote = { semgrep: 0, deps: 0 }
  for (const [fixture, items] of Object.entries(byFixture)) {
    const raw = readJson(join(OUT, fixture, 'raw.json'))
    const findings = raw?.findings || []
    const checks = raw?.checks || []
    if (checks.find((c) => /semgrep/i.test(c.agent) && c.status === 'skipped')) skippedNote.semgrep++
    if (checks.find((c) => /dependencies/i.test(c.agent) && c.status === 'skipped')) skippedNote.deps++
    const m = matchCatalog(findings, items)
    for (const r of m.items) {
      const c = (perCat[r.category] ||= { k: 0, n: 0 })
      c.n++; if (r.detected) c.k++; else missed.push(`${fixture}/${r.file}:${r.line} (${r.rule})`)
    }
  }
  const cats = Object.fromEntries(Object.entries(perCat).map(([c, v]) => [c, wilson(v.k, v.n)]))
  const totalK = Object.values(perCat).reduce((a, v) => a + v.k, 0)
  const totalN = Object.values(perCat).reduce((a, v) => a + v.n, 0)
  return { cats, overall: wilson(totalK, totalN), missed, skippedNote }
}

// ---------- PRECISÃO / FDR (de labels.csv, se houver) ----------
function precisionFromLabels() {
  const p = join(OUT, 'labels.csv')
  if (!existsSync(p)) return null
  const lines = readFileSync(p, 'utf8').split('\n').filter(Boolean)
  const header = lines.shift().split(',')
  const ci_ = header.indexOf('category'), vi = header.indexOf('verdict')
  const perCat = {}
  for (const ln of lines) {
    const cells = parseCsvLine(ln)
    const cat = cells[ci_], verdict = (cells[vi] || '').trim().toUpperCase()
    if (verdict !== 'TP' && verdict !== 'FP') continue
    const c = (perCat[cat] ||= { tp: 0, fp: 0 })
    if (verdict === 'TP') c.tp++; else c.fp++
  }
  if (!Object.keys(perCat).length) return { labeled: 0 }
  const out = { labeled: 0, cats: {} }
  let tTp = 0, tFp = 0
  for (const [cat, v] of Object.entries(perCat)) {
    const n = v.tp + v.fp; tTp += v.tp; tFp += v.fp; out.labeled += n
    out.cats[cat] = { precision: wilson(v.tp, n), fdr: wilson(v.fp, n), tp: v.tp, fp: v.fp }
  }
  out.overall = { precision: wilson(tTp, tTp + tFp), fdr: wilson(tFp, tTp + tFp) }
  return out
}
function parseCsvLine(ln) {
  const out = []; let cur = '', q = false
  for (let i = 0; i < ln.length; i++) { const ch = ln[i]
    if (q) { if (ch === '"' && ln[i + 1] === '"') { cur += '"'; i++ } else if (ch === '"') q = false; else cur += ch }
    else { if (ch === '"') q = true; else if (ch === ',') { out.push(cur); cur = '' } else cur += ch } }
  out.push(cur); return out
}

// ---------- MAIN ----------
function main() {
  const { records } = loadSummary()
  const real = records.filter((r) => r.stratum !== 'fixture')
  const outcomes = records.reduce((a, r) => ((a[r.outcome] = (a[r.outcome] || 0) + 1), a), {})
  const byStratum = {}
  for (const r of real) { (byStratum[r.stratum] ||= { repos: 0, findings: 0 }); byStratum[r.stratum].repos++; byStratum[r.stratum].findings += (r.findings || []).length }
  const recall = fixtureRecall()
  const prec = precisionFromLabels()
  const incumbents = readJson(join(OUT, 'incumbents.json'))
  const freeze = readJson(join(BENCH, 'corpus', 'freeze-report.json'))

  // ---- JSON (p/ fracta.pro) ----
  const json = {
    generatedAt: new Date().toISOString(),
    corpus: { totalRecords: records.length, realRepos: real.length, byStratum },
    robustness: outcomes,
    recall: recall && { overall: recall.overall, byCategory: recall.cats, skipped: recall.skippedNote, missedCount: recall.missed.length },
    precision: prec && (prec.labeled ? { labeled: prec.labeled, overall: prec.overall, byCategory: prec.cats } : { labeled: 0, status: 'pendente-rotulagem-humana' }),
    incumbentsAvailable: incumbents ? incumbents.rows?.length : 0,
    reproducibility: freeze ? { checked: freeze.total, ok: freeze.ok, drift: freeze.drift, vanished: freeze.vanished } : null,
  }
  writeFileSync(join(HERE, 'report.json'), JSON.stringify(json, null, 2))

  // ---- Markdown ----
  const L = []
  L.push('# Relatório de validação em escala — Fracta', '')
  L.push(`**Gerado:** ${json.generatedAt} · **Registros:** ${records.length} (${real.length} repos reais + ${records.length - real.length} fixtures)`, '')
  L.push('> Reproduzível: `pnpm bench:report` reconstrói estes números a partir de `results/summary.jsonl` (redigido, versionado) — sem re-clonar. A rodada cara é `bench:full`.', '')

  L.push('## Robustez (distribuição de desfechos)', '')
  L.push('| Desfecho | Repos |', '|---|---|')
  for (const [k, v] of Object.entries(outcomes)) L.push(`| ${k} | ${v} |`)
  L.push('')
  if (freeze) L.push(`Reprodutibilidade do corpus: ${freeze.ok} ok · ${freeze.drift} drift · ${freeze.vanished} sumiram (de ${freeze.total} verificados).`, '')

  L.push('## Recall (fixtures plantados — gabarito conhecido)', '')
  if (!recall) L.push('_Fixtures não escaneados. Rode `node bench/runner/run-batch.mjs --fixtures`._', '')
  else {
    L.push('| Categoria | Recall | IC 95% |', '|---|---|---|')
    for (const [c, r] of Object.entries(recall.cats)) L.push(`| ${c} | ${pct(r)} | ${ci(r)} |`)
    L.push(`| **geral** | **${pct(recall.overall)}** | **${ci(recall.overall)}** |`, '')
    if (recall.skippedNote.semgrep || recall.skippedNote.deps)
      L.push(`> ⚠️ Honestidade: SEMGREP pulou em ${recall.skippedNote.semgrep} fixture(s) e DEPENDENCIES em ${recall.skippedNote.deps} — \`skipped\` **≠** \`clean\`. SAST via semgrep é lento no Windows (roda em Linux/CI, ver Docker); deps exige lockfile+rede. Recall dessas categorias aqui é **piso**, não teto.`, '')
    if (recall.missed.length) { L.push('<details><summary>Itens não detectados (' + recall.missed.length + ')</summary>', ''); recall.missed.forEach((m) => L.push('- ' + m)); L.push('', '</details>', '') }
  }

  L.push('## Precisão / taxa de falsa-descoberta (amostra rotulada em repos reais)', '')
  if (!prec || !prec.labeled) {
    L.push('_Pendente rotulagem humana._ Gere a fila com `node bench/report/label-queue.mjs`, preencha `verdict` (TP/FP) e salve como `results/labels.csv`. A ferramenta **propõe**; o humano **confirma**.', '')
  } else {
    L.push('> **FDR** = FP/(TP+FP) na amostra (taxa de falsa-descoberta). **Não** é FPR verdadeiro — este exige o denominador de todos os sítios não-vulneráveis, que não temos. Nomear certo é a marca da casa.', '')
    L.push('| Categoria | Precisão | IC 95% | FDR | TP/FP |', '|---|---|---|---|---|')
    for (const [c, v] of Object.entries(prec.cats)) L.push(`| ${c} | ${pct(v.precision)} | ${ci(v.precision)} | ${pct(v.fdr)} | ${v.tp}/${v.fp} |`)
    L.push(`| **geral** | **${pct(prec.overall.precision)}** | **${ci(prec.overall.precision)}** | ${pct(prec.overall.fdr)} | — |`, '')
  }

  L.push('## Corpus por estrato', '')
  if (Object.keys(byStratum).length) { L.push('| Estrato | Repos | Findings |', '|---|---|---|'); for (const [s, v] of Object.entries(byStratum)) L.push(`| ${s} | ${v.repos} | ${v.findings} |`); L.push('') }
  else L.push('_Sem repos reais escaneados ainda (rode `bench:corpus` + `bench:run`)._', '')

  L.push('## Comparativa vs incumbentes', '')
  if (incumbents) L.push(`Cross-check disponível sobre ${incumbents.rows.length} alvo(s) (\`results/incumbents.json\`). Incumbentes são presos à pista (gitleaks→segredos, semgrep→SAST, trivy→deps); **LGPD = 0 para todos, não-zero só no Fracta**. A tabela conferida à mão (15/18) segue canônica em \`docs/benchmark.md\`.`, '')
  else L.push('_Cross-check não rodado (`node bench/crosscheck/run-incumbents.mjs`). Canônica hand-checked: `docs/benchmark.md` (15/18)._', '')
  L.push('')

  L.push('## O QUE ESTE BENCHMARK **NÃO** MEDE', '')
  L.push('- **DAST / runtime / auth / IDOR** — é 100% estático de repositório.')
  L.push('- **A população real de clientes.** Corpus público ≠ SaaS privados (onde o Fracta roda); recall/FDR **não transferem 1:1**. É estimativa de generalização.')
  L.push('- **Precisão fora da amostra rotulada** — é estimada (IC), não contada.')
  L.push('- **Categorias com tool ausente** (semgrep no Windows, deps sem lockfile/rede) — reportadas como `skipped`, nunca `clean`.')
  L.push('')

  writeFileSync(join(HERE, 'report.md'), L.join('\n') + '\n')
  console.log('Relatório gerado:')
  console.log('  bench/report/report.md')
  console.log('  bench/report/report.json')
  console.log(`Robustez: ${JSON.stringify(outcomes)}${recall ? ` · Recall geral fixtures: ${pct(recall.overall)} ${ci(recall.overall)}` : ''}`)
}

main()
