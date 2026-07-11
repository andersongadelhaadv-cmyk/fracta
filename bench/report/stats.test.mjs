import { test } from 'node:test'
import assert from 'node:assert/strict'
import { wilson } from './stats.mjs'

const close = (a, b, tol = 0.005) => Math.abs(a - b) <= tol

test('n=0 → no point estimate, full [0,1] interval', () => {
  const r = wilson(0, 0)
  assert.equal(r.point, null)
  assert.equal(r.low, 0)
  assert.equal(r.high, 1)
  assert.equal(r.n, 0)
})

test('5/10 at 95% → point 0.5, Wilson ~[0.237, 0.763]', () => {
  const r = wilson(5, 10)
  assert.equal(r.point, 0.5)
  assert.ok(close(r.low, 0.2366), `low ${r.low}`)
  assert.ok(close(r.high, 0.7634), `high ${r.high}`)
})

test('perfect 10/10 → point 1, high clamped to 1, low < 1', () => {
  const r = wilson(10, 10)
  assert.equal(r.point, 1)
  assert.equal(r.high, 1)
  assert.ok(r.low > 0.6 && r.low < 1, `low ${r.low}`)
})

test('0/10 → point 0, low clamped to 0, high > 0', () => {
  const r = wilson(0, 10)
  assert.equal(r.point, 0)
  assert.equal(r.low, 0)
  assert.ok(r.high > 0 && r.high < 0.4, `high ${r.high}`)
})

test('larger n narrows the interval (more data = tighter)', () => {
  const wide = wilson(50, 100)
  const tight = wilson(500, 1000)
  assert.ok((tight.high - tight.low) < (wide.high - wide.low), 'CI should shrink with n')
})

test('rejects k > n', () => {
  assert.throws(() => wilson(11, 10))
})
