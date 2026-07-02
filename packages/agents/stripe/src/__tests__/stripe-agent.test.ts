import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { StripeAgent } from '../index.js'
import type { ScanScope } from '@fracta/core'

const stripeScope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['stripe', 'nestjs'] },
  depth: 'full',
  agents: ['STRIPE Agent'],
  runId: 'run-1',
  startedAt: new Date(),
}

const noStripeScope: ScanScope = {
  ...stripeScope,
  target: { ...stripeScope.target, stack: ['nestjs'] },
}

describe('StripeAgent', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('skips silently when target stack does not include stripe', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(new Response('{}', { status: 200 }))
    )

    const findings = await new StripeAgent().run(noStripeScope)

    expect(findings).toHaveLength(0)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('não crasha em target sem stack (repo-only) — #34', async () => {
    const findings = await new StripeAgent().run({
      ...stripeScope,
      target: { name: 'repo-only', repoPath: '.' } as typeof stripeScope.target,
    })
    expect(findings).toHaveLength(0)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('emits info when stack has stripe but no webhook endpoint responds', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(() =>
      Promise.resolve(new Response('{}', { status: 404 }))
    )

    const findings = await new StripeAgent().run(stripeScope)

    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('info')
    expect(findings[0].title).toMatch(/nenhum endpoint de webhook/i)
  })

  it('flags critical when webhook accepts POST without Stripe-Signature', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string, init: RequestInit | undefined) => {
      if (url.includes('/api/stripe/webhook')) {
        const sig = (init?.headers as Record<string, string> | undefined)?.['Stripe-Signature']
        if (!sig) {
          return Promise.resolve(new Response('{"received":true}', { status: 200 }))
        }
        return Promise.resolve(new Response('{"received":true}', { status: 200 }))
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    const findings = await new StripeAgent().run(stripeScope)

    const noSig = findings.find(f => f.title.includes('sem assinatura'))
    expect(noSig).toBeDefined()
    expect(noSig?.severity).toBe('critical')

    const fakeSig = findings.find(f => f.title.includes('assinatura inválida'))
    expect(fakeSig).toBeDefined()
    expect(fakeSig?.severity).toBe('critical')
  })
})
