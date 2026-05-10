import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { IdorAgent } from '../index.js'
import type { ScanScope } from '@fracta/core'

const scopeNoAuth: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['nestjs'] },
  depth: 'quick',
  agents: ['IDOR Agent'],
  runId: 'run-1',
  startedAt: new Date(),
}

const scopeWithAuth: ScanScope = {
  ...scopeNoAuth,
  target: {
    ...scopeNoAuth.target,
    auth: { type: 'jwt' },
  },
}

describe('IdorAgent', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('emits info finding when target has no auth configured', async () => {
    const findings = await new IdorAgent().run(scopeNoAuth)

    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('info')
    expect(findings[0].title).toMatch(/autenticação não configurada/i)
  })

  it('flags critical IDOR when /users/{id} returns 200 with body', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/users/1') || url.includes('/users/2')) {
        return Promise.resolve(
          new Response('{"id":1,"email":"victim@example.com"}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    const findings = await new IdorAgent().run(scopeWithAuth)

    const idor = findings.find(f => f.severity === 'critical' && f.title.includes('IDOR'))
    expect(idor).toBeDefined()
  })
})
