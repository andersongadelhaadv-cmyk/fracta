import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { HeadersAgent } from '../index.js'
import type { ScanScope } from '@fracta/core'

const scope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['nextjs'] },
  depth: 'quick',
  agents: ['HEADERS Agent'],
  runId: 'run-1',
  startedAt: new Date(),
}

function responseWith(headers: Record<string, string>): Response {
  return new Response('<html></html>', { status: 200, headers })
}

describe('HeadersAgent', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('flags missing strict-transport-security header as high severity', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(responseWith({}))
    )

    const findings = await new HeadersAgent().run(scope)

    const hsts = findings.find(f => f.title.includes('strict-transport-security'))
    expect(hsts).toBeDefined()
    expect(hsts?.severity).toBe('high')
  })

  it('does NOT flag duplicated security headers as missing (helmet + nginx emit the same header twice)', async () => {
    // Em produção, o fetch junta headers repetidos numa string separada por vírgula
    // ("nosniff, nosniff"). O validador não pode tratar isso como ausente.
    const h = new Headers()
    h.append('strict-transport-security', 'max-age=31536000; includeSubDomains')
    h.append('strict-transport-security', 'max-age=63072000')
    h.append('x-content-type-options', 'nosniff')
    h.append('x-content-type-options', 'nosniff')
    h.append('x-frame-options', 'SAMEORIGIN')
    h.append('x-frame-options', 'SAMEORIGIN')
    h.append('referrer-policy', 'no-referrer')
    h.append('permissions-policy', 'geolocation=()')
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(new Response('<html></html>', { status: 200, headers: h }))
    )

    const findings = await new HeadersAgent().run(scope)
    const missing = findings.filter(f => f.title.startsWith('Security header ausente'))

    expect(missing).toEqual([])
  })

  it('still flags a genuinely wrong (conflicting) value among duplicates', async () => {
    const h = new Headers()
    h.append('strict-transport-security', 'max-age=31536000')
    h.append('x-content-type-options', 'nosniff')
    h.append('x-content-type-options', 'wrong')
    h.append('x-frame-options', 'SAMEORIGIN')
    h.append('referrer-policy', 'no-referrer')
    h.append('permissions-policy', 'geolocation=()')
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(new Response('<html></html>', { status: 200, headers: h }))
    )

    const findings = await new HeadersAgent().run(scope)
    const xcto = findings.find(f => f.title.includes('x-content-type-options'))

    expect(xcto).toBeDefined()
  })

  it('flags CORS wildcard as high', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(
        responseWith({
          'strict-transport-security': 'max-age=31536000',
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'no-referrer',
          'permissions-policy': 'geolocation=()',
          'access-control-allow-origin': '*',
        })
      )
    )

    const findings = await new HeadersAgent().run(scope)

    const cors = findings.find(f => f.title.includes('CORS wildcard'))
    expect(cors).toBeDefined()
    expect(cors?.severity).toBe('high')
  })

  // ─── Issue #11: stack-aware recommendations ────────────────────────────────

  it('(#11) nextjs stack: missing-header recommendation contains next.config snippet, NOT helmet/NestJS', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(responseWith({}))
    )

    // scope already has stack: ['nextjs']
    const findings = await new HeadersAgent().run(scope)

    const missing = findings.filter(f => f.title.startsWith('Security header ausente'))
    expect(missing.length).toBeGreaterThan(0)

    for (const f of missing) {
      expect(f.recommendation).toContain('next.config')
      expect(f.recommendation).not.toContain('NestJS')
      expect(f.recommendation).not.toContain('app.use(helmet())')
    }
  })

  it('(#11) empty stack: missing-header recommendation is neutral (no "helmet", no framework snippet)', async () => {
    const neutralScope: ScanScope = {
      ...scope,
      target: { ...scope.target, stack: [] },
    }

    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(responseWith({}))
    )

    const findings = await new HeadersAgent().run(neutralScope)

    const missing = findings.filter(f => f.title.startsWith('Security header ausente'))
    expect(missing.length).toBeGreaterThan(0)

    for (const f of missing) {
      expect(f.recommendation).not.toContain('helmet')
      expect(f.recommendation).not.toContain('NestJS')
      expect(f.recommendation).not.toContain('next.config')
    }
  })

  it('(#11) nestjs stack: missing-header recommendation uses helmet(); permissions-policy gets explicit override note', async () => {
    const nestScope: ScanScope = {
      ...scope,
      target: { ...scope.target, stack: ['nestjs'] },
    }

    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(responseWith({}))
    )

    const findings = await new HeadersAgent().run(nestScope)

    // Most headers should mention helmet
    const hsts = findings.find(f => f.title.includes('strict-transport-security'))
    expect(hsts?.recommendation).toContain('helmet()')

    // permissions-policy must note that helmet does NOT set it by default
    const pp = findings.find(f => f.title.includes('permissions-policy'))
    expect(pp?.recommendation).toContain('helmet')
    expect(pp?.recommendation).toContain('Permissions-Policy')
    // Should NOT just say "helmet() automatically" for permissions-policy
    expect(pp?.recommendation).not.toMatch(/inclui permissions-policy automaticamente/)
  })

  it('(#11) server: cloudflare → recommendation mentions CDN / cannot remove at origin', async () => {
    const allGoodHeaders = {
      'strict-transport-security': 'max-age=31536000',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()',
      'server': 'cloudflare',
    }

    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(responseWith(allGoodHeaders))
    )

    const findings = await new HeadersAgent().run(scope)

    const serverFinding = findings.find(f => f.title.includes('server'))
    expect(serverFinding).toBeDefined()
    // Must mention CDN/cannot-remove language
    expect(serverFinding?.recommendation?.toLowerCase()).toMatch(/cdn|provider|infraestrutura|cloudflare/)
    expect(serverFinding?.recommendation?.toLowerCase()).toContain('origem')
  })

  it('server SEM versão (CDN/proxy) → info (0 pts); COM versão → low', async () => {
    const base = {
      'strict-transport-security': 'max-age=31536000',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()',
    }
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>

    // sem versão → info
    fetchMock.mockImplementation(() => Promise.resolve(responseWith({ ...base, server: 'cloudflare' })))
    let findings = await new HeadersAgent().run(scope)
    let sf = findings.find(f => f.evidence?.startsWith('server:'))
    expect(sf).toBeDefined()
    expect(sf?.severity).toBe('info')

    // nginx puro (server_tokens off) → info
    fetchMock.mockImplementation(() => Promise.resolve(responseWith({ ...base, server: 'nginx' })))
    sf = (await new HeadersAgent().run(scope)).find(f => f.evidence?.startsWith('server:'))
    expect(sf?.severity).toBe('info')

    // COM versão → low (risco de fingerprinting)
    fetchMock.mockImplementation(() => Promise.resolve(responseWith({ ...base, server: 'nginx/1.24.0' })))
    sf = (await new HeadersAgent().run(scope)).find(f => f.evidence?.startsWith('server:'))
    expect(sf?.severity).toBe('low')

    fetchMock.mockImplementation(() => Promise.resolve(responseWith({ ...base, server: 'Apache/2.4.1 (Ubuntu)' })))
    sf = (await new HeadersAgent().run(scope)).find(f => f.evidence?.startsWith('server:'))
    expect(sf?.severity).toBe('low')
  })

  it('(#11) no recommendation in any finding contains the string "serverInfo"', async () => {
    const headers = {
      'server': 'Apache/2.4.41',
      'x-powered-by': 'PHP/7.4',
    }

    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(responseWith(headers))
    )

    const findings = await new HeadersAgent().run(scope)

    for (const f of findings) {
      expect(f.recommendation ?? '').not.toContain('serverInfo')
    }
  })
})
