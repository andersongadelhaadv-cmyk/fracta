import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyOutcome } from './outcome.mjs'

test('clean run with a report is ok', () => {
  assert.equal(classifyOutcome({ report: { findings: [] } }), 'ok')
})

test('timedOut flag wins over everything', () => {
  assert.equal(classifyOutcome({ timedOut: true, error: new Error('killed') }), 'timeout')
})

test('OOM error is classified as oom, not crash', () => {
  assert.equal(classifyOutcome({ error: new Error('JavaScript heap out of memory') }), 'oom')
  assert.equal(classifyOutcome({ error: 'spawn ENOMEM' }), 'oom')
})

test('any other error is a crash', () => {
  assert.equal(classifyOutcome({ error: new Error('boom') }), 'crash')
})

test('no report and no error is a crash (nothing produced)', () => {
  assert.equal(classifyOutcome({}), 'crash')
})
