import { describe, it, expect } from 'vitest'
import { LlmEnricher, applyEnrichment, parseModelJson } from '../index.js'
import type { LlmClient } from '../index.js'
import type { AuditReport, Finding } from '@fracta/core'

function finding(id: string, severity: Finding['severity'], withFix = false): Finding {
  return {
    id,
    runId: 'run-1',
    agent: 'A',
    category: 'security',
    camada: 'security',
    severity,
    status: 'open',
    title: `finding ${id}`,
    description: 'desc',
    recommendation: 'fix it',
    proposedFix: withFix
      ? { description: 'det fix', riskOfApplying: 'det risk' }
      : undefined,
    createdAt: new Date(),
  }
}

function report(findings: Finding[]): AuditReport {
  return {
    runId: 'run-1', saas: 'Demo', timestamp: new Date().toISOString(),
    target: 'Demo', startedAt: new Date(), finishedAt: new Date(), durationMs: 1,
    summary: { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings, passed: true,
    targetHealth: { repoAccessible: true, status: 'healthy' },
    checks: [],
    resumo: { porSeveridade: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, regressoes: 0, checksComErro: [], checksPulados: [] },
  }
}

function clientReturning(json: string): LlmClient {
  return { complete: async () => json }
}

describe('LlmEnricher', () => {
  it('is disabled (no-op) when there is no API key and no injected client', async () => {
    const enricher = new LlmEnricher({ apiKey: undefined })
    // ensure env key doesn't accidentally enable it for this assertion
    expect(enricher.enabled).toBe(process.env.ANTHROPIC_API_KEY ? true : false)
  })

  it('returns the report unchanged when disabled', async () => {
    const enricher = new LlmEnricher({})
    ;(enricher as unknown as { client?: unknown }).client = undefined // force disabled
    const r = report([finding('a', 'high')])
    expect(await enricher.enrich(r)).toBe(r)
  })

  it('does not call the model when there are no findings', async () => {
    let called = false
    const enricher = new LlmEnricher({ client: { complete: async () => { called = true; return '{}' } } })
    const r = report([])
    await enricher.enrich(r)
    expect(called).toBe(false)
  })

  it('applies prioritization order from the model', async () => {
    const r = report([finding('a', 'low'), finding('b', 'critical'), finding('c', 'medium')])
    const enricher = new LlmEnricher({
      client: clientReturning(JSON.stringify({ order: ['b', 'c', 'a'], rationale: 'crit first', fixes: [] })),
    })
    const out = await enricher.enrich(r)
    expect(out.prioritization?.order).toEqual(['b', 'c', 'a'])
    expect(out.prioritization?.rationale).toBe('crit first')
  })

  it('ignores invented ids and appends omitted ones (never invents/removes)', () => {
    const r = report([finding('a', 'low'), finding('b', 'high')])
    const out = applyEnrichment(r, { order: ['ghost', 'b'], fixes: [] })
    expect(out.prioritization?.order).toEqual(['b', 'a']) // ghost dropped, a appended
  })

  it('fills proposedFix only where missing and never overwrites a deterministic fix', () => {
    const r = report([finding('a', 'high', false), finding('b', 'high', true)])
    const out = applyEnrichment(r, {
      order: ['a', 'b'],
      fixes: [
        { id: 'a', description: 'llm fix', riskOfApplying: 'llm risk', command: 'do x' },
        { id: 'b', description: 'should-not-apply', riskOfApplying: 'nope' },
      ],
    })
    const a = out.findings.find(f => f.id === 'a')!
    const b = out.findings.find(f => f.id === 'b')!
    expect(a.proposedFix).toEqual({ description: 'llm fix', riskOfApplying: 'llm risk', command: 'do x' })
    expect(b.proposedFix).toEqual({ description: 'det fix', riskOfApplying: 'det risk' }) // untouched
  })

  it('rejects fixes missing riskOfApplying', () => {
    const r = report([finding('a', 'high', false)])
    const out = applyEnrichment(r, { order: ['a'], fixes: [{ id: 'a', description: 'no risk field' }] })
    expect(out.findings[0].proposedFix).toBeUndefined()
  })

  it('never changes severity or the set of findings', () => {
    const r = report([finding('a', 'low'), finding('b', 'critical')])
    const out = applyEnrichment(r, { order: ['b', 'a'], fixes: [] })
    expect(out.findings.map(f => f.id).sort()).toEqual(['a', 'b'])
    expect(out.findings.find(f => f.id === 'b')!.severity).toBe('critical')
    expect(out.findings.find(f => f.id === 'a')!.severity).toBe('low')
  })

  it('keeps the deterministic report when the model output is not parseable', async () => {
    const r = report([finding('a', 'high')])
    const enricher = new LlmEnricher({ client: clientReturning('I cannot help with that.') })
    const out = await enricher.enrich(r)
    expect(out.prioritization).toBeUndefined()
    expect(out).toEqual(r)
  })
})

describe('parseModelJson', () => {
  it('parses fenced json', () => {
    expect(parseModelJson('```json\n{"order":["x"]}\n```')).toEqual({ order: ['x'] })
  })
  it('parses json embedded in prose', () => {
    expect(parseModelJson('Sure! {"order":["y"]} done')).toEqual({ order: ['y'] })
  })
  it('returns null for non-json', () => {
    expect(parseModelJson('no json here')).toBeNull()
  })
})
