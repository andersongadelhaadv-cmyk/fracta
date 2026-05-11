import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { RaceAgent } from '../index.js'
import type { ScanScope } from '@fracta/core'

const quickScope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['nestjs'] },
  depth: 'quick',
  agents: ['RACE Agent'],
  runId: 'run-1',
  startedAt: new Date(),
}

const fullScope: ScanScope = { ...quickScope, depth: 'full' }

describe('RaceAgent', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('emits info finding and skips destructive bursts on depth=quick', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(new Response('{}', { status: 404 }))
    )

    const findings = await new RaceAgent().run(quickScope)

    const info = findings.find(f => f.severity === 'info' && f.title.includes('quick'))
    expect(info).toBeDefined()
    expect(globalThis.fetch).not.toHaveBeenCalledWith(
      expect.stringContaining('/api/coupons/redeem'),
      expect.anything()
    )
  })

  it('flags race condition when multiple concurrent POSTs succeed', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/api/coupons/redeem')) {
        return Promise.resolve(
          new Response('{"ok":true,"discount":10}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    const findings = await new RaceAgent().run(fullScope)

    const race = findings.find(f => f.title.includes('Race condition') && f.title.includes('/api/coupons/redeem'))
    expect(race).toBeDefined()
    expect(race?.severity).toBe('high')
  })

  it('does not flag when endpoint returns mostly 404', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(new Response('{}', { status: 404 }))
    )

    const findings = await new RaceAgent().run(fullScope)

    const race = findings.find(f => f.title.startsWith('Race condition'))
    expect(race).toBeUndefined()
  })
})
