#!/usr/bin/env node
// Gera os repos-FIXTURE do benchmark (Fase 3a) — recall EXATO contra gabarito conhecido.
//
// Princípio anti-fudge: o oráculo (catalog) é DERIVADO da mesma spec que gera os arquivos.
// A linha de cada item é COMPUTADA localizando o marcador no conteúdo — nunca digitada à mão —
// então o gabarito não pode divergir do que foi plantado.
//
// Segredos são SINTÉTICOS, montados por partes → nada com forma de credencial de provider fica
// versionado NESTE repo (respeita push-protection e o próprio auto-scan do Fracta).
//
//   node generate.mjs [out-dir]   → escreve fixtures em <out-dir>/<fixture>/ e catalog.json
import { mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

// ---- pseudo-aleatório determinístico (sem Math.random — reprodutível) ----
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz'
const R = (n, seed = 1) => Array.from({ length: n }, (_, i) => ALPHA[(i * 7 + seed * 13 + 11) % ALPHA.length]).join('')
const P = { aws: 'AK' + 'IA', stripe: 'sk' + '_' + 'live_', gh: 'gh' + 'p_', slack: 'xo' + 'xb-', npm: 'np' + 'm_' }
const pemLine = (b) => '-----' + b + ' RSA PRIVATE KEY-----'

// Localiza a linha (1-indexed) que contém `needle`. Falha alto se ausente (protege o oráculo).
function lineOf(content, needle) {
  const idx = content.split('\n').findIndex((l) => l.includes(needle))
  if (idx < 0) throw new Error(`marcador ausente no conteúdo: "${needle}"`)
  return idx + 1
}

// Constrói uma fixture: dir, arquivos, e itens de gabarito {file, marker, rule, category, severity}.
// A `line` é computada aqui a partir do marker → derivada, nunca manual.
function fx(dir, files, items) {
  const catalog = items.map((it) => ({
    fixture: dir,
    file: it.file,
    line: lineOf(files[it.file], it.marker),
    marker: it.marker,
    rule: it.rule,
    category: it.category,
    severity: it.severity || 'high',
    // sinal semântico TOOL-AGNÓSTICO (descreve a vuln, não a saída do Fracta): credita findings
    // repo-level sem localização. Escrito da ótica do ITEM plantado.
    signal: it.signal || null,
  }))
  return { fixture: { dir, files }, catalog }
}

export function buildFixtures() {
  const F = []

  // ---------- SEGREDOS (10) — marker = comentário-token na MESMA linha do segredo ----------
  const secrets = [
    ['sec-aws-key', 'src/aws.ts', `export const AWS_KEY = '${P.aws}${R(16, 2).toUpperCase().replace(/[^A-Z0-9]/g, '4')}' //@S:aws-access-key-id`, 'aws-access-key-id'],
    ['sec-aws-secret', 'src/aws.ts', `export const AWS_SECRET = '${R(40, 3)}' //@S:aws-secret-access-key`, 'aws-secret-access-key'],
    ['sec-stripe', 'src/pay.ts', `const stripe = '${P.stripe}${R(30, 4)}' //@S:stripe-live-key`, 'stripe-access-token'],
    ['sec-github-pat', 'src/gh.ts', `const token = '${P.gh}${R(36, 5)}' //@S:github-pat`, 'github-pat'],
    ['sec-generic', 'src/cfg.ts', `const API_KEY = '${R(48, 6).toLowerCase().replace(/[^a-z0-9]/g, '7')}' //@S:generic-api-key`, 'generic-api-key'],
    ['sec-slack', 'src/slack.ts', `const hook = '${P.slack}${R(24, 7)}' //@S:slack-token`, 'slack-access-token'],
    ['sec-npm', 'src/.npmrc', `//registry.npmjs.org/:_authToken=${P.npm}${R(36, 8)} //@S:npm-token`, 'npm-access-token'],
    ['sec-jwt', 'src/jwt.ts', `const JWT_SECRET = '${R(52, 9)}' //@S:jwt-secret`, 'jwt'],
    ['sec-gcp', 'src/gcp.ts', `const key = 'ya29.${R(60, 10)}' //@S:gcp-oauth`, 'gcp-api-key'],
  ]
  for (const [dir, file, line, rule] of secrets) {
    const content = `// fixture: segredo plantado (sintético)\n${line}\n`
    F.push(fx(dir, { [file]: content }, [{ file, marker: '@S:' + rule.split('-')[0], rule, category: 'secret', severity: 'critical' }]))
  }
  // 10ª: chave RSA privada em arquivo próprio
  {
    const dir = 'sec-rsa'
    const file = 'src/id_rsa'
    const content = pemLine('BEGIN') + '\n' + R(64, 11) + '\n' + R(64, 12) + '\n' + pemLine('END') + '\n'
    F.push(fx(dir, { [file]: content }, [{ file, marker: 'PRIVATE KEY', rule: 'private-key', category: 'secret', severity: 'critical' }]))
  }

  // ---------- SAST (8) ----------
  const sast = [
    ['sast-sqli', 'src/db.ts', `import { Pool } from 'pg'\nconst pool = new Pool()\nexport const get = (id) => pool.query("SELECT * FROM users WHERE id = " + id) //@V:sqli`, '@V:sqli', 'sql-injection'],
    ['sast-cmdi', 'src/sh.ts', `import { exec } from 'child_process'\nexport const ping = (h) => exec('ping -c 1 ' + h, () => {}) //@V:cmdi`, '@V:cmdi', 'command-injection'],
    ['sast-eval', 'src/calc.ts', `export const calc = (expr) => eval(expr) //@V:eval`, '@V:eval', 'eval-injection'],
    ['sast-xss', 'src/render.ts', `export const hello = (name, res) => res.send('<h1>Hello ' + name + '</h1>') //@V:xss`, '@V:xss', 'reflected-xss'],
    ['sast-pathtrav', 'src/file.ts', `import { readFileSync } from 'fs'\nexport const read = (p) => readFileSync('./data/' + p) //@V:pathtrav`, '@V:pathtrav', 'path-traversal'],
    ['sast-md5', 'src/hash.ts', `import { createHash } from 'crypto'\nexport const h = (s) => createHash('md5').update(s).digest('hex') //@V:weakhash`, '@V:weakhash', 'weak-hash'],
    ['sast-rand', 'src/token.ts', `export const token = () => Math.random().toString(36).slice(2) //@V:insecurerandom`, '@V:insecurerandom', 'insecure-random'],
    ['sast-ssrf', 'src/proxy.ts', `export const fetchUrl = (u) => fetch(u) //@V:ssrf`, '@V:ssrf', 'ssrf'],
  ]
  for (const [dir, file, content, marker, rule] of sast) {
    F.push(fx(dir, { [file]: content + '\n' }, [{ file, marker, rule, category: 'sast', severity: 'high' }]))
  }

  // ---------- DEPS (6) — CVE conhecidas; recall exige lockfile+rede (senão o agente SKIP) ----------
  const deps = [
    ['deps-lodash', 'lodash', '4.17.4'],
    ['deps-axios', 'axios', '0.18.0'],
    ['deps-jwt', 'jsonwebtoken', '8.5.1'],
    ['deps-minimist', 'minimist', '1.2.0'],
    ['deps-marked', 'marked', '0.3.6'],
    ['deps-nodefetch', 'node-fetch', '2.6.0'],
  ]
  for (const [dir, pkg, ver] of deps) {
    const file = 'package.json'
    const content = `{
  "name": "${dir}",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "${pkg}": "${ver}"
  }
}
`
    F.push(fx(dir, { [file]: content }, [{ file, marker: `"${pkg}": "${ver}"`, rule: `cve:${pkg}`, category: 'deps', severity: 'high' }]))
  }

  // ---------- LGPD (6) — o fosso; detectável 100% offline ----------
  // L1: política NEGA transferência internacional, mas o código a FAZ (contradição Art.33/Art.23)
  F.push(fx('lgpd-art33', {
    'app/privacidade/page.tsx': `export default function P(){return <p>Não realizamos transferência internacional de dados. //@L:art33-deny</p>}\n`,
    'src/analytics.ts': `import posthog from 'posthog-js'\nposthog.init('phc_x', { api_host: 'https://us.i.posthog.com' }) //@L:art33-intl-transfer\n`,
  }, [
    { file: 'src/analytics.ts', marker: '@L:art33-intl-transfer', rule: 'lgpd-art33-contradiction', category: 'lgpd', severity: 'high', signal: 'transfer[êe]ncia internacional|art\\.?\\s*33|contradi' },
  ]))
  // L2: operador não-declarado na política (Sentry usado, não citado)
  F.push(fx('lgpd-operador', {
    'src/monitor.ts': `import * as Sentry from '@sentry/node'\nSentry.init({ dsn: 'https://x@o0.ingest.sentry.io/0' }) //@L:undeclared-operator\n`,
    'app/privacidade/page.tsx': `export default function P(){return <p>Operadores: usamos apenas a Stripe.</p>}\n`,
  }, [
    { file: 'src/monitor.ts', marker: '@L:undeclared-operator', rule: 'lgpd-undeclared-operator', category: 'lgpd', severity: 'medium', signal: 'operador n[ãa]o declarado|undeclared operator|sub-?operador|sentry' },
  ]))
  // L3: dado pessoal sensível em log
  F.push(fx('lgpd-log', {
    'src/auth.ts': `export function login(cpf, senha){\n  console.log('login cpf=' + cpf + ' senha=' + senha) //@L:sensitive-in-log\n}\n`,
  }, [
    { file: 'src/auth.ts', marker: '@L:sensitive-in-log', rule: 'lgpd-sensitive-data-in-log', category: 'lgpd', severity: 'high', signal: 'sens[íi]vel.*log|dado.*em log|log.*(cpf|senha)' },
  ]))
  // L4: ROPA / inventário — schema com dados pessoais e sensíveis
  F.push(fx('lgpd-ropa', {
    'prisma/schema.prisma': `model User {\n  id    String @id\n  cpf   String //@L:ropa-personal\n  senha String\n  diagnostico String? //@L:ropa-sensitive\n}\n`,
  }, [
    { file: 'prisma/schema.prisma', marker: '@L:ropa-sensitive', rule: 'lgpd-ropa-sensitive', category: 'lgpd', severity: 'high', signal: 'ropa|invent[áa]rio de dados|dados pessoais.*schema' },
  ]))
  // L5: senha sem hashing
  F.push(fx('lgpd-senha', {
    'src/register.ts': `import { PrismaClient } from '@prisma/client'\nconst prisma = new PrismaClient()\nexport const reg = (email, senha) => prisma.user.create({ data: { email, senha } }) //@L:password-no-hash\n`,
  }, [
    { file: 'src/register.ts', marker: '@L:password-no-hash', rule: 'lgpd-password-no-hash', category: 'lgpd', severity: 'high', signal: 'senha sem hash|password.*hash|armazenamento de senha' },
  ]))
  // L6: ausência de política de privacidade num app que coleta dados pessoais
  F.push(fx('lgpd-sempolitica', {
    'prisma/schema.prisma': `model Lead {\n  id    String @id\n  email String //@L:collects-personal\n  telefone String\n}\n`,
    'README.md': `# App que coleta e-mail e telefone de leads\nSem página de privacidade.\n`,
  }, [
    { file: 'prisma/schema.prisma', marker: '@L:collects-personal', rule: 'lgpd-missing-privacy-policy', category: 'lgpd', severity: 'medium', signal: 'sem pol[íi]tica|pol[íi]tica de privacidade ausente|privacidade n[ãa]o encontrada' },
  ]))

  return {
    fixtures: F.map((x) => x.fixture),
    catalog: F.flatMap((x) => x.catalog),
  }
}

// ---------- CLI: escreve em disco ----------
function main() {
  const here = dirname(fileURLToPath(import.meta.url))
  const outDir = process.argv[2] || join(here, 'repos')
  const { fixtures, catalog } = buildFixtures()
  rmSync(outDir, { recursive: true, force: true })
  for (const fxt of fixtures) {
    for (const [rel, content] of Object.entries(fxt.files)) {
      const abs = join(outDir, fxt.dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content)
    }
  }
  writeFileSync(join(here, 'catalog.json'), JSON.stringify({ generatedFrom: 'generate.mjs', total: catalog.length, items: catalog }, null, 2) + '\n')
  const byCat = catalog.reduce((a, c) => ((a[c.category] = (a[c.category] || 0) + 1), a), {})
  console.log(`Fixtures: ${fixtures.length} repos, ${catalog.length} itens plantados em ${outDir}`)
  console.log('Por categoria:', JSON.stringify(byCat))
  console.log('Oráculo: bench/fixtures/catalog.json')
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('generate.mjs')) main()
