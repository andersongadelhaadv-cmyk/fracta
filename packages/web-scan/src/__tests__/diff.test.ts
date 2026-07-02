import { describe, it, expect } from 'vitest'
import { diffScans } from '../diff.js'
import type { PassiveScanResult, ScanGrade } from '../types.js'
import type { Finding } from '@fracta/core'

function finding(partial: Partial<Finding>): Finding {
  return {
    id: 'x', runId: 'r', agent: 'HEADERS', category: 'security', severity: 'medium',
    title: 't', description: 'd', recommendation: 'fix', createdAt: new Date(),
    ...partial,
  }
}

function scan(grade: ScanGrade | null, findings: Finding[]): PassiveScanResult {
  return {
    url: 'https://a.example', findings, grade,
    score: grade === null ? null : 100, verdict: grade === null ? 'inconclusive' : 'ok',
    checks: [], scannedAt: '2026-07-02T00:00:00.000Z',
  }
}

describe('diffScans', () => {
  it('scan idêntico → sem mudança, sem regressão', () => {
    const s = scan('A', [finding({ id: 'f1' })])
    const d = diffScans(s, s)
    expect(d.changed).toBe(false)
    expect(d.regressed).toBe(false)
    expect(d.gradeDelta).toBe('same')
    expect(d.newFindings).toHaveLength(0)
    expect(d.resolvedFindings).toHaveLength(0)
  })

  it('nota piora (A→C) → worsened + regressão', () => {
    const d = diffScans(scan('A', []), scan('C', []))
    expect(d.gradeDelta).toBe('worsened')
    expect(d.regressed).toBe(true)
    expect(d.changed).toBe(true)
  })

  it('novo achado aparece → listado + regressão', () => {
    const prev = scan('A', [finding({ id: 'f1', title: 'HSTS ok' })])
    const next = scan('A', [finding({ id: 'f1', title: 'HSTS ok' }), finding({ id: 'f2', title: 'CSP ausente', severity: 'high' })])
    const d = diffScans(prev, next)
    expect(d.newFindings.map(f => f.id)).toEqual(['f2'])
    expect(d.regressed).toBe(true)
  })

  it('achado resolvido + nota melhora (C→A) → resolvido listado, sem regressão', () => {
    const prev = scan('C', [finding({ id: 'f1' })])
    const next = scan('A', [])
    const d = diffScans(prev, next)
    expect(d.resolvedFindings.map(f => f.id)).toEqual(['f1'])
    expect(d.gradeDelta).toBe('improved')
    expect(d.regressed).toBe(false)
    expect(d.changed).toBe(true)
  })

  it('nota nula (inconclusivo) → gradeDelta unknown, nunca inventa regressão de nota', () => {
    const d = diffScans(scan('A', []), scan(null, []))
    expect(d.gradeDelta).toBe('unknown')
    expect(d.regressed).toBe(false)
  })

  it('identifica achados por assinatura estável quando falta id (severity::title)', () => {
    const prev = scan('A', [finding({ id: '', title: 'X', severity: 'low' })])
    const next = scan('A', [finding({ id: '', title: 'X', severity: 'low' })])
    expect(diffScans(prev, next).changed).toBe(false)
  })
})
