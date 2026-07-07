import { describe, it, expect, afterAll } from 'vitest'
import { mkdtemp, readFile, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { FractaReporter } from '../index.js'
import type { AuditReport } from '@fracta/core'

const dirs: string[] = []
afterAll(async () => { for (const d of dirs) await rm(d, { recursive: true, force: true }) })

function report(): AuditReport {
  return {
    runId: 'run-1', target: 'https://exemplo.com', startedAt: new Date('2026-07-07T00:00:00Z'),
    finishedAt: new Date('2026-07-07T00:00:05Z'), durationMs: 5000,
    summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    findings: [{
      id: 'sid-1', runId: 'run-1', agent: 'HEADERS Agent', category: 'security',
      severity: 'high', title: 'Sem HSTS', description: 'd', recommendation: 'r', createdAt: new Date(),
    }],
    passed: false, saas: 'exemplo', timestamp: '2026-07-07T00:00:05Z',
    targetHealth: { repoAccessible: true, status: 'healthy' }, checks: [],
    resumo: {
      porSeveridade: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      regressoes: 0, checksComErro: [], checksPulados: [], checksDegradados: [],
    },
  } as unknown as AuditReport
}

describe('FractaReporter.save → SARIF', () => {
  it('emite um arquivo .sarif válido junto do md/json', async () => {
    const out = await mkdtemp(join(tmpdir(), 'fracta-sarif-')); dirs.push(out)
    const r = await new FractaReporter({ outputDir: out, toolVersion: '1.2.3' }).save(report())
    expect(r.sarifPath).toMatch(/\.sarif$/)
    const sarif = JSON.parse(await readFile(r.sarifPath, 'utf-8'))
    expect(sarif.version).toBe('2.1.0')
    expect(sarif.runs[0].tool.driver.version).toBe('1.2.3')
    expect(sarif.runs[0].results[0].partialFingerprints.fractaFindingId).toBe('sid-1')
    expect(sarif.runs[0].results[0].level).toBe('error') // high → error
  })
})
