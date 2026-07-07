import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { IdorAgent } from '../index.js'
import type { ScanScope } from '@fracta/core'

const scope: ScanScope = {
  target: {
    name: 'demo', url: 'http://example.test', stack: [],
    auth: { type: 'jwt', endpoint: '/api/auth/login', credentials: { email: 'a@x', password: 'pa' } },
    crossTenant: { credentials: { email: 'b@x', password: 'pb' }, ownedResources: ['/api/processos/42'] },
    // sem os PATH_TEMPLATES/ENUM baterem (ignore tudo menos o cross-tenant)
    ignore: ['/users', '/api/users', '/api/v1', '/api/v2', '/clientes', '/api/clientes', '/invoices', '/api/invoices', '/subscriptions', '/api/subscriptions', '/reports', '/api/reports', '/documents', '/api/documents', '/calculos', '/api/calculos', '/processos', '/api/processos'],
  },
  depth: 'quick', agents: ['IDOR Agent'], runId: 'run-1', startedAt: new Date(),
}

/** Mock que distingue A de B pelo token e simula o comportamento do recurso de B. */
function mockFetch(resourceForA: (authz: string) => Response) {
  return vi.fn((url: string, init: { method?: string; headers?: Record<string, string>; body?: string }) => {
    const u = String(url)
    if (u.includes('/api/auth/login')) {
      const email = JSON.parse(init.body ?? '{}').email
      const token = email === 'a@x' ? 'tok-A' : 'tok-B'
      return Promise.resolve(new Response(JSON.stringify({ token }), { status: 200, headers: { 'content-type': 'application/json' } }))
    }
    const authz = init.headers?.Authorization ?? ''
    if (u.includes('/api/processos/42')) {
      if (authz === 'Bearer tok-B') return Promise.resolve(new Response('{"owner":"B"}', { status: 200, headers: { 'content-type': 'application/json' } }))
      if (authz === 'Bearer tok-A') return Promise.resolve(resourceForA(authz))
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

describe('IdorAgent — cross-tenant (2 contas)', () => {
  beforeEach(() => {})
  afterEach(() => { vi.unstubAllGlobals() })

  it('CONFIRMA vazamento: A lê o recurso que pertence a B (200) → critical VERIFIED', async () => {
    vi.stubGlobal('fetch', mockFetch(() => new Response('{"owner":"B","dados":"sigilosos"}', { status: 200, headers: { 'content-type': 'application/json' } })))
    const findings = await new IdorAgent().run(scope)
    const hit = findings.find(f => f.severity === 'critical' && /cross-tenant CONFIRMADO/i.test(f.title))
    expect(hit, JSON.stringify(findings.map(f => f.title))).toBeTruthy()
    expect(hit!.endpoint).toBe('/api/processos/42')
    expect(hit!.confidence).toBe('high')
  })

  it('ISOLAMENTO ok: A é negado (403) no recurso de B → info prova positiva, sem crítico', async () => {
    vi.stubGlobal('fetch', mockFetch(() => new Response('', { status: 403 })))
    const findings = await new IdorAgent().run(scope)
    expect(findings.some(f => f.severity === 'critical')).toBe(false)
    const iso = findings.find(f => /isolamento multi-tenant confirmado/i.test(f.title))
    expect(iso, JSON.stringify(findings.map(f => f.title))).toBeTruthy()
    expect(iso!.severity).toBe('info')
  })
})
