import { describe, it, expect } from 'vitest'
import { toSarif } from '../sarif.js'
import type { AuditReport, Finding } from '@fracta/core'

function finding(p: Partial<Finding> & Pick<Finding, 'id' | 'title' | 'severity'>): Finding {
  return {
    runId: 'run-1', agent: 'HEADERS Agent', category: 'security',
    description: 'desc', recommendation: 'fix', createdAt: new Date('2026-07-07T00:00:00Z'), ...p,
  }
}
function report(findings: Finding[]): AuditReport {
  return {
    runId: 'run-1', target: 'https://exemplo.com', startedAt: new Date('2026-07-07T00:00:00Z'),
    finishedAt: new Date('2026-07-07T00:00:05Z'), durationMs: 5000,
    summary: { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings, passed: false, saas: 'exemplo', timestamp: '2026-07-07T00:00:05Z',
    targetHealth: { repoAccessible: true, status: 'healthy' }, checks: [],
  } as unknown as AuditReport
}

describe('toSarif', () => {
  it('produz um SARIF 2.1.0 válido com o driver Fracta', () => {
    const s = toSarif(report([finding({ id: 'a1', title: 'X', severity: 'high' })]), { toolVersion: '9.9.9' })
    expect(s.version).toBe('2.1.0')
    expect(s.$schema).toMatch(/sarif.*2\.1\.0/i)
    expect(s.runs[0].tool.driver.name).toBe('Fracta')
    expect(s.runs[0].tool.driver.version).toBe('9.9.9')
  })

  it('mapeia severidade → level SARIF (error/warning/note)', () => {
    const s = toSarif(report([
      finding({ id: 'c', title: 'crit', severity: 'critical' }),
      finding({ id: 'h', title: 'high', severity: 'high' }),
      finding({ id: 'm', title: 'med', severity: 'medium' }),
      finding({ id: 'l', title: 'low', severity: 'low' }),
      finding({ id: 'i', title: 'info', severity: 'info' }),
    ]))
    const level = (id: string) => s.runs[0].results.find(r => r.partialFingerprints.fractaFindingId === id)!.level
    expect(level('c')).toBe('error')
    expect(level('h')).toBe('error')
    expect(level('m')).toBe('warning')
    expect(level('l')).toBe('note')
    expect(level('i')).toBe('note')
  })

  it('carrega o id ESTÁVEL como partialFingerprint (é o que dá diff/suppress no GitHub)', () => {
    const s = toSarif(report([finding({ id: 'stable-123', title: 'X', severity: 'medium' })]))
    expect(s.runs[0].results[0].partialFingerprints.fractaFindingId).toBe('stable-123')
  })

  it('deduplica regras e referencia ruleId nos results', () => {
    const s = toSarif(report([
      finding({ id: '1', title: 'A', severity: 'high', agent: 'HEADERS Agent', category: 'security' }),
      finding({ id: '2', title: 'B', severity: 'high', agent: 'HEADERS Agent', category: 'security' }),
    ]))
    // mesmo agente+categoria → 1 regra só
    expect(s.runs[0].tool.driver.rules).toHaveLength(1)
    const ruleId = s.runs[0].tool.driver.rules[0].id
    expect(s.runs[0].results.every(r => r.ruleId === ruleId)).toBe(true)
  })

  it('usa endpoint como localização do artefato quando presente', () => {
    const s = toSarif(report([finding({ id: '1', title: 'X', severity: 'high', endpoint: 'src/app.ts' })]))
    const loc = s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri
    expect(loc).toBe('src/app.ts')
  })
})
