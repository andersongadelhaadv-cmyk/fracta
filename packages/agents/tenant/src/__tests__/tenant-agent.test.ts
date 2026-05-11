import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { TenantAgent } from '../index.js'
import type { ScanScope } from '@fracta/core'

const baseScope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['nestjs'] },
  depth: 'quick',
  agents: ['TENANT Agent'],
  runId: 'run-1',
  startedAt: new Date(),
}

describe('TenantAgent', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('emits info finding when target has no auth configured', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(new Response('{}', { status: 404 }))
    )

    const findings = await new TenantAgent().run(baseScope)

    const info = findings.find(f => f.severity === 'info')
    expect(info).toBeDefined()
    expect(info?.title).toMatch(/autentica/i)
  })

  it('flags exposed admin route as high without authentication', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/api/admin/users')) {
        return Promise.resolve(
          new Response('{"users":[{"id":1}]}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    const findings = await new TenantAgent().run(baseScope)

    const admin = findings.find(f => f.title.includes('/api/admin/users'))
    expect(admin).toBeDefined()
    expect(admin?.severity).toBe('high')
  })

  it('flags cross-tenant access when multiple IDs respond 200', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/api/orgs/1/users') || url.includes('/api/orgs/2/users')) {
        return Promise.resolve(
          new Response('{"users":[{"id":1}]}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    const findings = await new TenantAgent().run(baseScope)

    const cross = findings.find(f => f.title.includes('Cross-tenant') && f.title.includes('/api/orgs/{id}/users'))
    expect(cross).toBeDefined()
    expect(cross?.severity).toBe('critical')
  })
})
