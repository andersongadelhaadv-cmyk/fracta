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
})
