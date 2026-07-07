import { describe, it, expect } from 'vitest'
import { evaluateCrossTenant, type CrossTenantProbe } from '../cross-tenant.js'

const base = { saas: 'demo', runId: 'run-1' }

describe('evaluateCrossTenant', () => {
  it('A acessando recurso de B (200+corpo) que B possui = IDOR cross-tenant CONFIRMADO (critical, VERIFIED)', () => {
    const probes: CrossTenantProbe[] = [
      { resource: '/api/processos/42', tenantBStatus: 200, tenantAStatus: 200, tenantABytes: 500, tenantABody: '{"segredo":"de B"}' },
    ]
    const f = evaluateCrossTenant({ ...base, probes })
    const hit = f.find(x => x.severity === 'critical')
    expect(hit, JSON.stringify(f)).toBeTruthy()
    expect(hit!.confidence).toBe('high')
    expect(hit!.endpoint).toBe('/api/processos/42')
    expect(hit!.title).toMatch(/cross-tenant|CONFIRMADO/i)
    expect(hit!.references?.some(r => /639/.test(r))).toBe(true)
  })

  it('A negado (403/404) em todos os recursos que B possui = isolamento CONFIRMADO (info, prova positiva)', () => {
    const probes: CrossTenantProbe[] = [
      { resource: '/api/processos/42', tenantBStatus: 200, tenantAStatus: 403, tenantABytes: 0 },
      { resource: '/api/clientes/7', tenantBStatus: 200, tenantAStatus: 404, tenantABytes: 0 },
    ]
    const f = evaluateCrossTenant({ ...base, probes })
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('info')
    expect(f[0].title).toMatch(/isolamento|isolado/i)
    expect(f[0].description).toMatch(/2/) // 2 recursos testados
  })

  it('B não acessa os próprios recursos = INCONCLUSIVO (nunca verde falso), não confirma nem isola', () => {
    const probes: CrossTenantProbe[] = [
      { resource: '/api/processos/42', tenantBStatus: 401, tenantAStatus: 404, tenantABytes: 0 },
    ]
    const f = evaluateCrossTenant({ ...base, probes })
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('info')
    expect(f[0].title).toMatch(/inconclus/i)
  })

  it('mistura: um confirmado + um isolado → emite o CRÍTICO (o vazamento manda)', () => {
    const probes: CrossTenantProbe[] = [
      { resource: '/api/a/1', tenantBStatus: 200, tenantAStatus: 403, tenantABytes: 0 },
      { resource: '/api/b/2', tenantBStatus: 200, tenantAStatus: 200, tenantABytes: 300 },
    ]
    const f = evaluateCrossTenant({ ...base, probes })
    expect(f.some(x => x.severity === 'critical' && x.endpoint === '/api/b/2')).toBe(true)
  })

  it('sem probes = nenhum finding (no-op)', () => {
    expect(evaluateCrossTenant({ ...base, probes: [] })).toEqual([])
  })
})
