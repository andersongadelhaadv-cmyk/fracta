import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { AuthAgent } from '../index.js'
import type { ScanScope } from '@fracta/core'

const scope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['nestjs'] },
  depth: 'quick',
  agents: ['AUTH Agent'],
  runId: 'run-1',
  startedAt: new Date(),
}

function mockResponse(status: number, body = '{"ok":true,"data":"sensitive"}'): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('AuthAgent', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('flags unauthenticated endpoint returning HTTP 200 as critical', async () => {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>
    fetchMock.mockImplementation((url: string) =>
      Promise.resolve(
        url.includes('/api/users') ? mockResponse(200) : mockResponse(401, '{"error":"unauthorized"}')
      )
    )

    const findings = await new AuthAgent().run(scope)

    const critical = findings.filter(f => f.severity === 'critical')
    expect(critical.length).toBeGreaterThan(0)
    expect(critical[0].title).toMatch(/Endpoint desprotegido|Token malformado/)
  })

  it('emits info finding when no auth endpoint is configured', async () => {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>
    fetchMock.mockImplementation(() => Promise.resolve(mockResponse(401, '{}')))

    const findings = await new AuthAgent().run(scope)

    const rateLimitInfo = findings.find(f =>
      f.severity === 'info' && f.title.toLowerCase().includes('rate limit')
    )
    expect(rateLimitInfo).toBeDefined()
  })
})
