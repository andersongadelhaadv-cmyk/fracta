#!/usr/bin/env node
// Fase 3b — prepara a FILA DE REVISÃO p/ rotular precisão em repos reais. Amostra estratificada
// por categoria (determinística, reprodutível: ordena por hash do finding-id, sem Math.random),
// com contexto pronto p/ o humano decidir rápido: trecho (redigido) + PERMALINK no SHA congelado.
//
// Regra: a ferramenta PROPÕE o rótulo (TP, pois o Fracta flagrou); o HUMANO confirma TP/FP em
// results/labels.csv. detect ≠ correct vale p/ rótulo.
//
//   node label-queue.mjs [--per 40]
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { sampleSizeFor } from './stats.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const BENCH = join(HERE, '..')
const OUT = join(BENCH, 'results')
const argv = process.argv.slice(2)
const flag = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 ? argv[i + 1] : d }
// default: n p/ margem de IC ~±13% (Wilson no pior caso) → ~57/categoria; ajustável.
const PER = flag('per') ? Number(flag('per')) : sampleSizeFor(0.13)

const h = (s) => createHash('sha256').update(String(s)).digest('hex')
const csvCell = (v) => { const s = String(v ?? ''); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s }

function collectCandidates() {
  if (!existsSync(OUT)) return []
  const out = []
  for (const id of readdirSync(OUT)) {
    const dir = join(OUT, id)
    if (!statSync(dir).isDirectory() || id.startsWith('_')) continue
    // Fixtures têm gabarito (recall) → NÃO vão p/ rotulagem manual. Repo real sempre é owner__name.
    if (!id.includes('__')) continue
    const rawP = join(dir, 'raw.json'), outP = join(dir, 'outcome.json')
    if (!existsSync(rawP)) continue
    let raw, meta
    try { raw = JSON.parse(readFileSync(rawP, 'utf8')) } catch { continue }
    try { meta = JSON.parse(readFileSync(outP, 'utf8')) } catch { meta = {} }
    if (!Array.isArray(raw.findings)) continue
    const [owner, name] = id.split('__')
    const sha = meta.sha || raw.sha || null
    for (const f of raw.findings || []) {
      const file = f.location?.file, line = f.location?.line
      const permalink = owner && name && sha && file
        ? `https://github.com/${owner}/${name}/blob/${sha}/${String(file).replace(/\\/g, '/')}${line ? '#L' + line : ''}`
        : ''
      out.push({
        finding_id: f.id, repo: `${owner}/${name}`, category: f.camada || f.category,
        rule: (f.title || '').slice(0, 60), file, line, severity: f.severity, confidence: f.confidence,
        permalink, evidence: (f.evidence || f.description || '').replace(/\s+/g, ' ').slice(0, 220),
        proposed_label: 'TP',
      })
    }
  }
  return out
}

function stratifiedSample(cands, per) {
  const byCat = {}
  for (const c of cands) (byCat[c.category] ||= []).push(c)
  const picked = []
  const summary = {}
  for (const [cat, list] of Object.entries(byCat)) {
    list.sort((a, b) => h(a.finding_id).localeCompare(h(b.finding_id))) // ordem determinística
    const take = list.slice(0, per)
    picked.push(...take)
    summary[cat] = { available: list.length, sampled: take.length }
  }
  return { picked, summary }
}

function main() {
  const cands = collectCandidates()
  if (!cands.length) { console.log('Sem findings em repos reais ainda (rode bench:run sobre o manifest).'); return }
  const { picked, summary } = stratifiedSample(cands, PER)

  const cols = ['finding_id', 'repo', 'category', 'rule', 'file', 'line', 'severity', 'confidence', 'proposed_label', 'verdict', 'notes', 'permalink', 'evidence']
  const rows = [cols.join(',')]
  for (const p of picked) rows.push(cols.map((c) => csvCell(c === 'verdict' ? '' : c === 'notes' ? '' : p[c])).join(','))
  const queuePath = join(OUT, 'label-queue.csv')
  writeFileSync(queuePath, rows.join('\n') + '\n')

  console.log(`Fila de rotulagem: ${picked.length} findings amostrados (n alvo/categoria=${PER})`)
  console.log('Por categoria:', JSON.stringify(summary))
  console.log(`→ ${queuePath}`)
  console.log('Preencha a coluna `verdict` (TP/FP) e salve como results/labels.csv. O relatório calcula precisão + IC de Wilson a partir dela.')
}

main()
