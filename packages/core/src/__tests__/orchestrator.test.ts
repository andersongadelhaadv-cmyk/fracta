import { describe, it, expect, vi } from 'vitest'
import { FractaOrchestrator } from '../orchestrator.js'
import { SkippedCheck } from '../types.js'
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

  it('isolates a throwing agent: others still complete and it is recorded as error', async () => {
    const good = makeAgent('Good', [makeFinding('Good', 'high')])
    const bad: SecurityAgent = {
      name: 'Bad', category: 'security', concurrency: 1, timeoutMs: 1_000,
      run: async () => { throw new Error('boom') },
    }
    const orch = new FractaOrchestrator({ concurrency: 2 })
    orch.registerAgents([good, bad])

    const report = await orch.scan(target)

    expect(good.run).toHaveBeenCalledOnce()
    expect(report.findings).toHaveLength(1) // só os do Good
    expect(report.resumo.checksComErro).toContain('Bad')
    const badCheck = report.checks.find(c => c.agent === 'Bad')
    expect(badCheck?.status).toBe('error')
    expect(badCheck?.motivo).toContain('boom')
  })

  it('marks a SkippedCheck as skipped with motivo, not error', async () => {
    const skip: SecurityAgent = {
      name: 'NeedsRepo', category: 'deps', concurrency: 1, timeoutMs: 1_000,
      run: async () => { throw new SkippedCheck('sem repoPath') },
    }
    const orch = new FractaOrchestrator()
    orch.registerAgent(skip)

    const report = await orch.scan(target)

    expect(report.resumo.checksPulados).toContain('NeedsRepo')
    expect(report.resumo.checksComErro).not.toContain('NeedsRepo')
    const check = report.checks.find(c => c.agent === 'NeedsRepo')
    expect(check?.status).toBe('skipped')
    expect(check?.motivo).toBe('sem repoPath')
  })

  it('times out a hanging agent and records it as error', async () => {
    const hang: SecurityAgent = {
      name: 'Hang', category: 'security', concurrency: 1, timeoutMs: 20,
      run: () => new Promise<Finding[]>(resolve => setTimeout(() => resolve([]), 200)),
    }
    const orch = new FractaOrchestrator()
    orch.registerAgent(hang)

    const report = await orch.scan(target)

    const check = report.checks.find(c => c.agent === 'Hang')
    expect(check?.status).toBe('error')
    expect(check?.motivo).toContain('timeout')
  })

  it('defaults camada and status on findings that omit them', async () => {
    const orch = new FractaOrchestrator({ failOn: [] })
    orch.registerAgent(makeAgent('A', [makeFinding('A', 'low')]))

    const report = await orch.scan(target)

    expect(report.findings[0].camada).toBe('security')
    expect(report.findings[0].status).toBe('open')
  })
})
