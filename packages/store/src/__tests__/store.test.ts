import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { SqliteFindingStore } from '../index.js'
import type { Finding, AuditReport } from '@fracta/core'

function finding(id: string, severity: Finding['severity'] = 'high'): Finding {
  return {
    id,
    runId: 'run-x',
    agent: 'TestAgent',
    category: 'security',
    camada: 'security',
    severity,
    title: `finding ${id}`,
    description: 'test',
    recommendation: 'fix it',
    createdAt: new Date(),
  }
}

let store: SqliteFindingStore

describe('SqliteFindingStore', () => {
  beforeEach(() => {
    store = new SqliteFindingStore(':memory:')
  })
  afterEach(() => {
    store.close()
  })

  it('marks a brand-new finding as open', () => {
    const [f] = store.applyStatus('DemoSaaS', [finding('a')], [])
    expect(f.status).toBe('open')
  })

  it('keeps a finding open across consecutive runs where it stays present', () => {
    store.applyStatus('DemoSaaS', [finding('a')], [])
    const [f] = store.applyStatus('DemoSaaS', [finding('a')], [])
    expect(f.status).toBe('open')
  })

  it('flags a finding that disappeared and came back as regression', () => {
    store.applyStatus('DemoSaaS', [finding('a')], []) // run 1: aparece
    store.applyStatus('DemoSaaS', [], [])             // run 2: some → resolvido
    const [f] = store.applyStatus('DemoSaaS', [finding('a')], []) // run 3: volta
    expect(f.status).toBe('regression')
  })

  it('marks a suppressed id as suppressed and out of the open noise', () => {
    const [f] = store.applyStatus('DemoSaaS', [finding('a')], ['a'])
    expect(f.status).toBe('suppressed')
  })

  it('isolates history per saas (same id in another saas is independent)', () => {
    store.applyStatus('SaasA', [finding('a')], [])
    const [f] = store.applyStatus('SaasB', [finding('a')], [])
    expect(f.status).toBe('open') // não vira regressão por causa do outro SaaS
  })

  it('persists the run via recordRun', () => {
    const report = {
      runId: 'run-1',
      saas: 'DemoSaaS',
      timestamp: new Date().toISOString(),
      target: 'DemoSaaS',
      startedAt: new Date(),
      finishedAt: new Date(),
      durationMs: 1,
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings: [],
      passed: true,
      targetHealth: { repoAccessible: true, status: 'healthy' as const },
      checks: [],
      resumo: { porSeveridade: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, regressoes: 0, checksComErro: [], checksPulados: [] },
    } satisfies AuditReport

    expect(() => store.recordRun(report)).not.toThrow()
  })
})
