import { test } from 'node:test'
import assert from 'node:assert/strict'
import { redactSecrets } from './redact.mjs'

// Segredos-de-teste montados POR PARTES: nada com forma de credencial de provider fica versionado
// (respeita a push-protection do próprio repo — a ferramenta que redige segredos não pode plantar um).
const aws = 'AK' + 'IA' + 'IOSFODNN7EXAMPLE'
const stripe = 'sk' + '_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc'

test('masks a provider-prefixed AWS key but keeps a locatable stub', () => {
  const out = redactSecrets(`key = '${aws}'`)
  assert.ok(!out.includes(aws), 'raw key must not survive')
  assert.match(out, /‹redacted:[0-9a-f]{8}›/, 'must leave a stable redaction stub')
})

test('masks a stripe live key', () => {
  const out = redactSecrets(`const s = "${stripe}"`)
  assert.ok(!out.includes(stripe))
})

test('masks a long high-entropy token (>=32 chars)', () => {
  const tok = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0'
  assert.ok(!redactSecrets('token=' + tok).includes(tok))
})

test('masks a PEM private-key body', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----'
  const out = redactSecrets(pem)
  assert.ok(!out.includes('MIIEpAIBAAKCAQEA7'), 'key body must be masked')
})

test('does NOT over-redact ordinary file paths or prose', () => {
  const s = 'src/config-secrets.ts:4 — Stripe live secret key hardcoded'
  assert.equal(redactSecrets(s), s, 'must leave normal evidence text untouched')
})

test('is deterministic — same secret redacts to the same stub', () => {
  assert.equal(redactSecrets(`k='${aws}'`), redactSecrets(`k='${aws}'`))
})

test('handles non-string input gracefully', () => {
  assert.equal(redactSecrets(undefined), undefined)
  assert.equal(redactSecrets(null), null)
})
