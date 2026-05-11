import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { SupabaseSkill } from '../index.js'
import type { ScanScope } from '@fracta/core'

const scope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['supabase'] },
  depth: 'full',
  agents: ['Supabase Skill'],
  runId: 'run-1',
  startedAt: new Date(),
}

describe('SupabaseSkill', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('skips when stack does not declare supabase', async () => {
    const findings = await new SupabaseSkill().run({
      ...scope,
      target: { ...scope.target, stack: ['nextjs'] },
    })
    expect(findings).toHaveLength(0)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('flags REST root accessible without apikey as medium', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.endsWith('/rest/v1/')) {
        return Promise.resolve(
          new Response('{"swagger":"2.0","paths":{}}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      }
      return Promise.resolve(new Response('{}', { status: 401 }))
    })

    const findings = await new SupabaseSkill().run(scope)
    const rest = findings.find(f => f.title.includes('REST root'))
    expect(rest).toBeDefined()
    expect(rest?.severity).toBe('medium')
  })

  it('flags critical when anon key reads rows from a common table', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string, init: RequestInit | undefined) => {
      const hasApiKey = !!(init?.headers as Record<string, string> | undefined)?.apikey
      if (hasApiKey && url.includes('/rest/v1/profiles')) {
        return Promise.resolve(
          new Response('[{"id":1,"email":"a@b.com"},{"id":2,"email":"c@d.com"}]', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      }
      return Promise.resolve(new Response('{}', { status: 401 }))
    })

    const skill = new SupabaseSkill({ anonKey: 'fake-anon-key' })
    const findings = await skill.run(scope)
    const rls = findings.find(f => f.title.includes('RLS off') && f.title.includes('profiles'))
    expect(rls).toBeDefined()
    expect(rls?.severity).toBe('critical')
  })
})
