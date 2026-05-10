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
