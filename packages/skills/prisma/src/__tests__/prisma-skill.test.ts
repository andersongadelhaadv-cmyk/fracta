import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { PrismaSkill } from '../index.js'
import type { ScanScope } from '@fracta/core'

const scope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: ['prisma', 'nestjs'] },
  depth: 'full',
  agents: ['Prisma Skill'],
  runId: 'run-1',
  startedAt: new Date(),
}

describe('PrismaSkill', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('skips when stack does not declare prisma', async () => {
    const findings = await new PrismaSkill().run({
      ...scope,
      target: { ...scope.target, stack: ['nestjs'] },
    })
    expect(findings).toHaveLength(0)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('não crasha em target sem stack (repo-only) — #34', async () => {
    const findings = await new PrismaSkill().run({
      ...scope,
      target: { name: 'repo-only', repoPath: '.' } as typeof scope.target,
    })
    expect(findings).toHaveLength(0)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })

  it('flags exposed Prisma Studio as critical', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/prisma-studio')) {
        return Promise.resolve(
          new Response('<html><title>Prisma Studio</title></html>', { status: 200 })
        )
      }
      return Promise.resolve(new Response('Not Found', { status: 404 }))
    })

    const findings = await new PrismaSkill().run(scope)
    const studio = findings.find(f => f.title.includes('Studio'))
    expect(studio).toBeDefined()
    expect(studio?.severity).toBe('critical')
  })

  it('flags Prisma error leak as medium', async () => {
    ;(globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation((url: string) => {
      if (url.includes('/api/users')) {
        return Promise.resolve(
          new Response(
            '{"message":"PrismaClientKnownRequestError: Invalid `prisma.user.create()` invocation. Unique constraint failed on the fields: (`email`) - P2002"}',
            { status: 500, headers: { 'content-type': 'application/json' } }
          )
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    const findings = await new PrismaSkill().run(scope)
    const leak = findings.find(f => f.title.includes('Erro Prisma'))
    expect(leak).toBeDefined()
    expect(leak?.severity).toBe('medium')
  })
})
