import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NestJSSkill } from '../index.js'
import type { ScanScope } from '@fracta/core'

const scope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['nestjs'] },
  depth: 'full',
  agents: ['NestJS Skill'],
  runId: 'run-1',
  startedAt: new Date(),
}

describe('NestJSSkill', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('skips when stack does not declare nestjs', async () => {
    const findings = await new NestJSSkill().run({
      ...scope,
      target: { ...scope.target, stack: ['nextjs'] },
    })
    expect(findings).toHaveLength(0)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('flags exposed Swagger UI as high', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/api/docs')) {
        return Promise.resolve(
          new Response('<html><body><div id="swagger-ui"></div></body></html>', { status: 200 })
        )
      }
      return Promise.resolve(new Response('Not Found', { status: 404 }))
    })

    const findings = await new NestJSSkill().run(scope)
    const swagger = findings.find(f => f.title.includes('Swagger'))
    expect(swagger).toBeDefined()
    expect(swagger?.severity).toBe('high')
  })

  it('flags health endpoint leaking env vars as medium', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/health')) {
        return Promise.resolve(
          new Response('{"status":"ok","DATABASE_URL":"postgres://leak"}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    const findings = await new NestJSSkill().run(scope)
    const health = findings.find(f => f.title.includes('Health endpoint'))
    expect(health).toBeDefined()
    expect(health?.severity).toBe('medium')
  })
})
