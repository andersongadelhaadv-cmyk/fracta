#!/usr/bin/env node
// Fase 1 — seleciona o corpus via GitHub API (gh) com query DECLARADA e congela o SHA + treeSha.
// O treeSha (hash do conteúdo da árvore, do objeto commit) é a âncora de reprodutibilidade:
// um terceiro que faça fetch do mesmo SHA obtém o mesmo tree.sha → provou que pegou os MESMOS bits.
// Sem clonar nada aqui — tudo via `gh api`.
//
//   node build-manifest.mjs                    # todos os estratos, contagem cheia
//   node build-manifest.mjs --stratum br-lgpd  # só um estrato
//   node build-manifest.mjs --limit 3          # piloto: só N repos por estrato
//   --force  (re-consulta mesmo com manifest existente)
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { parse as parseYaml, stringify as toYaml } from 'yaml'

const HERE = dirname(fileURLToPath(import.meta.url))
const argv = process.argv.slice(2)
const flag = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 ? argv[i + 1] : d }
const has = (n) => argv.includes('--' + n)
const ONLY = flag('stratum')
const PER = flag('limit') ? Number(flag('limit')) : Infinity
const MANIFEST = join(HERE, 'manifest.yaml')

function gh(path, params = {}) {
  const args = ['api', '-X', 'GET', path, '-H', 'Accept: application/vnd.github+json']
  for (const [k, v] of Object.entries(params)) args.push('-f', `${k}=${v}`)
  try {
    return JSON.parse(execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }))
  } catch (e) {
    const msg = (e.stderr || e.stdout || e.message || '').toString().slice(0, 300)
    throw new Error(`gh api ${path} falhou: ${msg}`)
  }
}

function selectStratum(s, defaults) {
  const q = `${s.query} ${defaults.qualifiers}`.trim()
  const want = Math.min(s.count, PER)
  const res = gh('search/repositories', { q, sort: defaults.sort, order: defaults.order, per_page: String(Math.min(100, want)) })
  const items = (res.items || []).slice(0, want)
  const repos = []
  for (const it of items) {
    try {
      // resolve o HEAD do default branch → sha + treeSha (hash de conteúdo)
      const commit = gh(`repos/${it.owner.login}/${it.name}/commits/${it.default_branch}`)
      repos.push({
        owner: it.owner.login, name: it.name, url: it.clone_url,
        stars: it.stargazers_count, defaultBranch: it.default_branch,
        sha: commit.sha, treeSha: commit.commit?.tree?.sha ?? null,
        sizeKb: it.size, stratum: s.key,
      })
    } catch (e) {
      console.error(`  ! pulou ${it.owner.login}/${it.name}: ${e.message}`)
    }
  }
  return repos
}

function main() {
  const cfg = parseYaml(readFileSync(join(HERE, 'query.yaml'), 'utf8'))
  const strata = cfg.strata.filter((s) => !ONLY || s.key === ONLY)

  let existing = { repos: [] }
  if (existsSync(MANIFEST) && !has('force')) existing = parseYaml(readFileSync(MANIFEST, 'utf8')) || existing
  const byId = new Map((existing.repos || []).map((r) => [`${r.owner}/${r.name}`, r]))

  for (const s of strata) {
    console.log(`Estrato ${s.key}: "${s.query}"`)
    const repos = selectStratum(s, cfg.defaults)
    for (const r of repos) byId.set(`${r.owner}/${r.name}`, r) // REGRA DE OURO: nunca remove; só adiciona/atualiza
    console.log(`  +${repos.length} repos`)
  }

  const manifest = {
    version: 1,
    generatedAt: new Date().toISOString(),
    method: 'GitHub search/repositories via gh; SHA e treeSha congelados por repo',
    queries: cfg.strata.map((s) => ({ stratum: s.key, query: `${s.query} ${cfg.defaults.qualifiers}`.trim(), count: s.count })),
    total: byId.size,
    repos: [...byId.values()].sort((a, b) => a.stratum.localeCompare(b.stratum) || b.stars - a.stars),
  }
  writeFileSync(MANIFEST, toYaml(manifest))
  const byStratum = manifest.repos.reduce((a, r) => ((a[r.stratum] = (a[r.stratum] || 0) + 1), a), {})
  console.log(`Manifest: ${manifest.total} repos →`, JSON.stringify(byStratum))
  console.log('Gravado em', MANIFEST)
}

main()
