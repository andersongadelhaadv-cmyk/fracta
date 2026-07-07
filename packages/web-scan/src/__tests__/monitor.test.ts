import { describe, it, expect, vi } from 'vitest'
import { runMonitor, type MonitorDeps } from '../monitor.js'
import type { PassiveScanResult, ScanGrade } from '../types.js'
import type { Finding } from '@fracta/core'

const finding = (id: string, severity: Finding['severity'] = 'high'): Finding =>
  ({ id, runId: 'r', agent: 'HEADERS', category: 'headers', severity, title: id, description: '', recommendation: '', createdAt: new Date() }) as unknown as Finding

const res = (url: string, grade: ScanGrade | null, findings: Finding[] = []): PassiveScanResult => ({
  url, findings, grade, score: grade ? 100 : null, verdict: grade ? 'ok' : 'inconclusive',
  checks: [{ name: 'security-headers', status: grade ? 'ok' : 'skipped' }], scannedAt: '2026-07-07T00:00:00.000Z',
})

/** deps fake: 1 assinatura, um scan "anterior" fixo e um "atual" parametrizável. */
function deps(prev: PassiveScanResult | null, current: PassiveScanResult): { deps: MonitorDeps; markNotified: ReturnType<typeof vi.fn>; saveScan: ReturnType<typeof vi.fn> } {
  const markNotified = vi.fn()
  const saveScan = vi.fn(() => 'new-share-id')
  return {
    markNotified, saveScan,
    deps: {
      listActive: () => [{ id: 1, email: 'a@ex.com', url: current.url, unsubToken: 'tok', lastNotifiedScanId: null }],
      getLastScan: () => (prev ? { shareId: 'prev-id', result: prev } : null),
      scan: async () => current,
      saveScan,
      markNotified,
    },
  }
}

describe('runMonitor', () => {
  it('REGRESSÃO (nota caiu) → 1 alerta + markNotified + salva o scan novo', async () => {
    const { deps: d, markNotified, saveScan } = deps(res('https://x.com', 'A'), res('https://x.com', 'D'))
    const alerts = await runMonitor(d)
    expect(alerts).toHaveLength(1)
    expect(alerts[0].diff.regressed).toBe(true)
    expect(alerts[0].shareId).toBe('new-share-id')
    expect(saveScan).toHaveBeenCalledOnce()
    expect(markNotified).toHaveBeenCalledWith(1, 'new-share-id')
  })

  it('REGRESSÃO (achado novo, mesma nota) → alerta', async () => {
    const { deps: d } = deps(res('https://x.com', 'B', [finding('hsts')]), res('https://x.com', 'B', [finding('hsts'), finding('csp')]))
    expect(await runMonitor(d)).toHaveLength(1)
  })

  it('MESMA nota e achados → 0 alertas (não re-notifica "ainda ruim")', async () => {
    const { deps: d } = deps(res('https://x.com', 'D'), res('https://x.com', 'D'))
    expect(await runMonitor(d)).toHaveLength(0)
  })

  it('MELHOROU → 0 alertas', async () => {
    const { deps: d } = deps(res('https://x.com', 'D'), res('https://x.com', 'A'))
    expect(await runMonitor(d)).toHaveLength(0)
  })

  it('BASELINE (sem scan anterior) → 0 alertas, mas salva o scan', async () => {
    const { deps: d, saveScan } = deps(null, res('https://x.com', 'D'))
    expect(await runMonitor(d)).toHaveLength(0)
    expect(saveScan).toHaveBeenCalledOnce()
  })

  it('INCONCLUSIVO (nota nula) → 0 alertas (nunca regressão inventada)', async () => {
    const { deps: d } = deps(res('https://x.com', 'A'), res('https://x.com', null))
    expect(await runMonitor(d)).toHaveLength(0)
  })

  it('scan que FALHA → pula honesto, sem alerta e sem crash', async () => {
    const d: MonitorDeps = {
      listActive: () => [{ id: 1, email: 'a@ex.com', url: 'https://x.com', unsubToken: 't', lastNotifiedScanId: null }],
      getLastScan: () => ({ shareId: 'p', result: res('https://x.com', 'A') }),
      scan: async () => { throw new Error('rede') },
      saveScan: vi.fn(() => 'id'),
      markNotified: vi.fn(),
    }
    expect(await runMonitor(d)).toHaveLength(0)
  })
})
