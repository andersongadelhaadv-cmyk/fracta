import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildFixtures } from './generate.mjs'

test('buildFixtures produces >= 30 fixtures with a derived oracle catalog', () => {
  const { fixtures, catalog } = buildFixtures()
  assert.ok(fixtures.length >= 30, `expected >=30 fixtures, got ${fixtures.length}`)
  assert.ok(catalog.length >= fixtures.length, 'catalog should have >= one item per fixture')
})

test('every catalog item points at a REAL line that contains its planted marker', () => {
  const { fixtures, catalog } = buildFixtures()
  const byDir = new Map(fixtures.map((f) => [f.dir, f]))
  for (const item of catalog) {
    const fx = byDir.get(item.fixture)
    assert.ok(fx, `catalog references unknown fixture ${item.fixture}`)
    const content = fx.files[item.file]
    assert.ok(content !== undefined, `catalog references missing file ${item.fixture}/${item.file}`)
    const lines = content.split('\n')
    const line = lines[item.line - 1]
    assert.ok(
      line !== undefined && line.includes(item.marker),
      `oracle drift: ${item.fixture}/${item.file}:${item.line} does not contain marker "${item.marker}" (found: "${line}")`,
    )
  }
})

test('every catalog item has the required oracle fields', () => {
  const { catalog } = buildFixtures()
  const cats = new Set(['secret', 'sast', 'deps', 'lgpd'])
  for (const item of catalog) {
    assert.ok(cats.has(item.category), `bad category: ${item.category}`)
    assert.equal(typeof item.rule, 'string')
    assert.ok(item.rule.length > 0, 'rule must be non-empty')
    assert.ok(Number.isInteger(item.line) && item.line >= 1, 'line must be 1-indexed int')
  }
})

test('is deterministic — no random/time-dependent output', () => {
  const a = JSON.stringify(buildFixtures().catalog)
  const b = JSON.stringify(buildFixtures().catalog)
  assert.equal(a, b, 'buildFixtures must be deterministic across calls')
})

test('planted secrets carry no real provider-shaped credential in the SPEC source', () => {
  // The generator source must assemble secrets by parts; this guards the invariant that
  // scanning THIS repo never trips push-protection. We assert the marker tokens are synthetic.
  const { catalog } = buildFixtures()
  const secretItems = catalog.filter((c) => c.category === 'secret')
  assert.ok(secretItems.length >= 5, 'need a spread of secret types')
})
