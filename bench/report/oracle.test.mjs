import { test } from 'node:test'
import assert from 'node:assert/strict'
import { matchCatalog } from './oracle.mjs'

const item = (over = {}) => ({ fixture: 'f', file: 'src/pay.ts', line: 2, category: 'secret', rule: 'stripe', ...over })
const finding = (over = {}) => ({ location: { file: 'src/pay.ts', line: 2 }, category: 'code', agent: 'STACK Agent', camada: 'code', ...over })

test('detects when file suffix + exact line match (even if agent lane differs)', () => {
  const r = matchCatalog([finding()], [item()])
  assert.equal(r.items[0].detected, true)
  assert.equal(r.detected, 1)
})

test('path-suffix match tolerates absolute/relative prefixes and backslashes', () => {
  const f = finding({ location: { file: 'C:\\clone\\src\\pay.ts', line: 2 } })
  assert.equal(matchCatalog([f], [item()]).items[0].detected, true)
})

test('line within tolerance (±3) still counts', () => {
  assert.equal(matchCatalog([finding({ location: { file: 'src/pay.ts', line: 5 } })], [item()]).items[0].detected, true)
})

test('line beyond tolerance does NOT count', () => {
  assert.equal(matchCatalog([finding({ location: { file: 'src/pay.ts', line: 20 } })], [item()]).items[0].detected, false)
})

test('file-level finding with no line credits a file match (repo-level LGPD)', () => {
  const f = finding({ location: { file: 'prisma/schema.prisma' }, agent: 'COMPLIANCE Agent', camada: 'compliance' })
  const it = item({ file: 'prisma/schema.prisma', line: 4, category: 'lgpd' })
  assert.equal(matchCatalog([f], [it]).items[0].detected, true)
})

test('different file never matches', () => {
  assert.equal(matchCatalog([finding({ location: { file: 'src/other.ts', line: 2 } })], [item()]).items[0].detected, false)
})

test('reports category agreement as a stat without gating detection', () => {
  // STACK/code flags a secret → detected true, but categoryAgree false (lane differs)
  const r = matchCatalog([finding()], [item()])
  assert.equal(r.items[0].detected, true)
  assert.equal(r.items[0].categoryAgree, false)
})

test('empty findings → nothing detected', () => {
  const r = matchCatalog([], [item(), item({ file: 'a.ts' })])
  assert.equal(r.detected, 0)
  assert.equal(r.total, 2)
})

test('credits a finding whose file:line is only in the TITLE (repo-level location)', () => {
  const f = { title: 'Possível dado sensível em log: src/auth.ts:2', agent: 'COMPLIANCE Agent', camada: 'compliance' }
  const it = item({ file: 'src/auth.ts', line: 2, category: 'lgpd', signal: 'sens[íi]vel.*log' })
  assert.equal(matchCatalog([f], [it]).items[0].detected, true)
})

test('credits a location-less finding via tool-agnostic semantic SIGNAL', () => {
  const f = { title: 'Possível armazenamento de senha sem hashing', agent: 'COMPLIANCE Agent', camada: 'compliance' }
  const it = item({ file: 'src/register.ts', line: 3, category: 'lgpd', signal: 'senha sem hash' })
  assert.equal(matchCatalog([f], [it]).items[0].detected, true)
})

test('signal match is not blocked by an incidental file mentioned in EVIDENCE', () => {
  // Real case: evidence "package.json sem bcrypt... senha detectada" must not hijack location.
  const f = { title: 'Possível armazenamento de senha sem hashing', evidence: 'package.json sem bcrypt/argon2 + escrita de senha detectada no código.', agent: 'COMPLIANCE Agent', camada: 'compliance' }
  const it = item({ file: 'src/register.ts', line: 3, category: 'lgpd', signal: 'senha sem hash|armazenamento de senha' })
  assert.equal(matchCatalog([f], [it]).items[0].detected, true)
})

test('a generic compliance finding does NOT match an item whose signal it fails', () => {
  // "Criptografia não evidenciada" fires on every repo — must NOT credit the missing-policy item.
  const f = { title: 'Criptografia em trânsito/repouso não evidenciada', agent: 'COMPLIANCE Agent', camada: 'compliance' }
  const it = item({ file: 'prisma/schema.prisma', line: 2, category: 'lgpd', signal: 'sem pol[íi]tica|privacidade ausente' })
  assert.equal(matchCatalog([f], [it]).items[0].detected, false)
})
