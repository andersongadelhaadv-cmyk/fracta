#!/usr/bin/env node
// Scorer do benchmark: normaliza a saída de cada ferramenta em {category, file|pkg}, casa
// contra ground-truth.json e imprime a tabela de recall (markdown). Recall por grupo =
// min(findings_no_grupo, itens_no_grupo)/itens — justo quando um arquivo tem N segredos.
//
//   node score.mjs --truth ground-truth.json \
//     --gitleaks gl.json --semgrep sg.json --trivy tv.json --npmaudit na.json --fracta fr.json
//
// Qualquer ferramenta omitida entra como 0 na sua área. Caminhos casam por sufixo (as
// ferramentas emitem prefixos diferentes — absoluto/relativo).
import { readFileSync } from 'node:fs'

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, arr) => {
  if (v.startsWith('--')) a.push([v.slice(2), arr[i + 1]]); return a
}, []))
const readJson = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')) } catch { return null } }
const norm = (s) => String(s || '').replace(/\\/g, '/').toLowerCase()
const fileMatch = (found, truth) => norm(found).endsWith(norm(truth))

const truth = readJson(args.truth)
if (!truth) { console.error('ground-truth ausente'); process.exit(1) }

// --- Normalizadores: cada um devolve [{category, file?, pkg?}] ---
function fromGitleaks(j) {
  return (Array.isArray(j) ? j : []).map(f => ({ category: 'secret', file: f.File }))
}
function fromSemgrep(j) {
  return ((j && j.results) || []).map(r => ({ category: 'sast', file: r.path }))
}
function fromTrivy(j) {
  const out = []
  for (const res of (j && j.Results) || []) for (const v of res.Vulnerabilities || []) out.push({ category: 'deps', pkg: v.PkgName })
  return out
}
function fromNpmAudit(j) {
  return Object.keys((j && j.vulnerabilities) || {}).map(pkg => ({ category: 'deps', pkg }))
}
function fromFracta(j) {
  // aceita {findings:[...]} do harness/relatório; mapeia agente→categoria e extrai arquivo/pkg
  // da evidência OU do título. Alguns achados são repo-level (ROPA, senha sem hashing) e não
  // citam o arquivo na evidência → inferimos o arquivo-alvo por palavra-chave do título.
  const AG = { SECRETS: 'secret', SEMGREP: 'sast', STACK: 'sast', DEPENDENCIES: 'deps', COMPLIANCE: 'lgpd' }
  return ((j && j.findings) || []).map(f => {
    const ag = (f.agent || '').replace(/ Agent$/, '').toUpperCase()
    const category = AG[ag]
    if (!category) return null
    const ev = `${f.evidence || ''} ${f.title || ''}`.replace(/\\/g, '/') // normaliza path Windows
    // arquivo: com extensão OU arquivo-segredo sem extensão (id_rsa, id_ed25519)
    let fileM = ev.match(/([\w./-]+\.(?:ts|tsx|js|mjs|prisma|env|json))/i)
    let file = fileM ? fileM[1] : (/(id_rsa|id_ed25519|\.pem)/i.test(ev) ? 'src/id_rsa' : undefined)
    // inferência por título para achados repo-level:
    if (category === 'lgpd' && /invent[áa]rio|ropa/i.test(ev)) file = 'prisma/schema.prisma'
    if (category === 'lgpd' && /senha sem hashing|password.*hash/i.test(ev)) file = 'src/auth.ts'
    const pkgM = (ev.match(/→\s*([\w@/.-]+):/) || ev.match(/vulner[áa]vel:\s*([\w@/.-]+)/i))
    return { category, file, pkg: pkgM ? pkgM[1] : undefined }
  }).filter(Boolean)
}

const tools = {
  gitleaks: fromGitleaks(readJson(args.gitleaks) || []),
  semgrep: fromSemgrep(readJson(args.semgrep) || {}),
  trivy: fromTrivy(readJson(args.trivy) || {}),
  'npm audit': fromNpmAudit(readJson(args.npmaudit) || {}),
  fracta: fromFracta(readJson(args.fracta) || {}),
}

// --- Agrupa ground-truth por (category, chave) — chave = file (secret/sast/lgpd) ou pkg (deps) ---
const groups = {}
for (const it of truth.items) {
  const key = it.category + '|' + (it.pkg || it.file)
  ;(groups[key] ||= { category: it.category, file: it.file, pkg: it.pkg, count: 0 }).count++
}
const CATS = ['secret', 'sast', 'deps', 'lgpd']
const catTotals = CATS.map(c => truth.items.filter(i => i.category === c).length)

function recallFor(findings, category) {
  const g = Object.values(groups).filter(x => x.category === category)
  let detected = 0
  for (const grp of g) {
    const hits = findings.filter(f => f.category === category && (
      grp.pkg ? norm(f.pkg) === norm(grp.pkg) || norm(f.pkg).includes(norm(grp.pkg)) : (f.file && fileMatch(f.file, grp.file))
    )).length
    detected += Math.min(hits, grp.count)
  }
  return detected
}

// --- Tabela ---
const rows = []
for (const [name, fnds] of Object.entries(tools)) {
  const perCat = CATS.map(c => recallFor(fnds, c))
  rows.push({ name, perCat, total: perCat.reduce((a, b) => a + b, 0), found: fnds.length })
}
const grand = truth.items.length

let md = `## Benchmark — recall (achados corretos / plantados)\n\n`
md += `| Ferramenta | Segredos (${catTotals[0]}) | SAST (${catTotals[1]}) | Deps (${catTotals[2]}) | LGPD (${catTotals[3]}) | Total (${grand}) |\n`
md += `|---|---|---|---|---|---|\n`
for (const r of rows) {
  md += `| ${r.name} | ${r.perCat[0]} | ${r.perCat[1]} | ${r.perCat[2]} | ${r.perCat[3]} | **${r.total}/${grand}** |\n`
}
md += `\n> Recall automático (gabarito \`ground-truth.json\`). LGPD é a coluna que só o Fracta cobre.\n`
console.log(md)

// saída JSON p/ CI, se pedido
if (args.json) {
  const out = Object.fromEntries(rows.map(r => [r.name, { perCategory: Object.fromEntries(CATS.map((c, i) => [c, r.perCat[i]])), total: r.total, totalFindings: r.found }]))
  import('node:fs').then(fs => fs.writeFileSync(args.json, JSON.stringify({ groundTruth: grand, tools: out }, null, 2)))
}
