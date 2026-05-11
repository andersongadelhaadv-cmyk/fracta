import { describe, it, expect, vi } from 'vitest'
import { FractaOrchestrator } from '../orchestrator.js'
import type { SecurityAgent, ScanScope, Finding, Target } from '../types.js'

function makeAgent(name: string, findings: Finding[] = []): SecurityAgent {
  return {
    name,
    category: 'security',
    concurrency: 1,
    timeoutMs: 1_000,
    run: vi.fn(async (_scope: ScanScope) => findings),
  }
}

function makeFinding(agent: string, severity: Finding['severity'] = 'high'): Finding {
  return {
    id: `id-${agent}`,
    runId: 'run-x',
    agent,
    category: 'security',
    severity,
    title: `${agent} finding`,
    description: 'test',
    recommendation: 'fix it',
    createdAt: new Date(),
  }
}

const target: Target = { name: 'demo', url: 'http://example.test', stack: ['nestjs'] }

describe('FractaOrchestrator', () => {
  it('runs every registered agent and aggregates findings', async () => {
    const a = makeAgent('A', [makeFinding('A', 'critical')])
    const b = makeAgent('B', [makeFinding('B', 'low')])
    const c = makeAgent('C', [])

    const orch = new FractaOrchestrator({ concurrency: 2, failOn: ['critical'] })
    orch.registerAgents([a, b, c])

    const report = await orch.scan(target)

    expect(a.run).toHaveBeenCalledOnce()
    expect(b.run).toHaveBeenCalledOnce()
    expect(c.run).toHaveBeenCalledOnce()
    expect(report.findings).toHaveLength(2)
    expect(report.summary.critical).toBe(1)
    expect(report.summary.low).toBe(1)
    expect(report.passed).toBe(false)
  })

  it('passes when no failOn severity is hit', async () => {
    const orch = new FractaOrchestrator({ failOn: ['critical'] })
    orch.registerAgent(makeAgent('A', [makeFinding('A', 'low')]))

    const report = await orch.scan(target)

    expect(report.passed).toBe(true)
    expect(report.summary.critical).toBe(0)
  })

  it('runs agents in parallel chunks bounded by concurrency', async () => {
    const calls: string[] = []
    const slow = (name: string): SecurityAgent => ({
      name,
      category: 'security',
      concurrency: 1,
      timeoutMs: 1_000,
      run: async () => {
        calls.push(`start-${name}`)
        await new Promise(r => setTimeout(r, 10))
        calls.push(`end-${name}`)
        return []
      },
    })

    const orch = new FractaOrchestrator({ concurrency: 2 })
    orch.registerAgents([slow('A'), slow('B'), slow('C')])

    await orch.scan(target)

    expect(calls.slice(0, 2).sort()).toEqual(['start-A', 'start-B'])
    expect(calls).toContain('end-C')
  })

  it('filters agents based on target.agents allowlist', async () => {
    const a = makeAgent('Keep')
    const b = makeAgent('Drop')
    const orch = new FractaOrchestrator()
    orch.registerAgents([a, b])

    await orch.scan({ ...target, agents: ['Keep'] })

    expect(a.run).toHaveBeenCalledOnce()
    expect(b.run).not.toHaveBeenCalled()
  })
})
