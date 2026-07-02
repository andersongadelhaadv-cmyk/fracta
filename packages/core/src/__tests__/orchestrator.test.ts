import { describe, it, expect, vi } from 'vitest'
import { FractaOrchestrator } from '../orchestrator.js'
import type { OrchestratorOptions } from '../orchestrator.js'
import { SkippedCheck } from '../types.js'
import type { SecurityAgent, ScanScope, Finding, Target, TargetHealth } from '../types.js'

// Stub de saúde p/ manter os testes herméticos (sem rede no preflight).
const HEALTHY = async (): Promise<TargetHealth> => ({ repoAccessible: true, status: 'healthy' })
function makeOrch(opts: OrchestratorOptions = {}): FractaOrchestrator {
  return new FractaOrchestrator({ healthCheck: HEALTHY, ...opts })
}

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

    const orch = makeOrch({ concurrency: 2, failOn: ['critical'] })
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
    const orch = makeOrch({ failOn: ['critical'] })
    orch.registerAgent(makeAgent('A', [makeFinding('A', 'low')]))

    const report = await orch.scan(target)

    expect(report.passed).toBe(true)
    expect(report.summary.critical).toBe(0)
  })

  it('não falha quando o achado de severidade failOn está suprimido (falso-positivo revisado)', async () => {
    const supp: Finding = { ...makeFinding('A', 'high'), status: 'suppressed' }
    const orch = makeOrch({ failOn: ['critical', 'high'] })
    orch.registerAgent(makeAgent('A', [supp]))

    const report = await orch.scan(target)

    expect(report.summary.high).toBe(0) // suprimido fora da conta de severidade
    expect(report.passed).toBe(true) // e fora do pass/fail
    expect(report.findings).toHaveLength(1) // mas segue no relatório p/ transparência
  })

  it('achado failOn de confiança BAIXA aparece mas NÃO derruba o build', async () => {
    const lo: Finding = { ...makeFinding('A', 'high'), confidence: 'low' }
    const orch = makeOrch({ failOn: ['critical', 'high'] })
    orch.registerAgent(makeAgent('A', [lo]))

    const report = await orch.scan(target)

    expect(report.passed).toBe(true) // confiança baixa não falha
    expect(report.summary.high).toBe(1) // mas é mostrado (transparência)
  })

  it('rebaixa (verificação) achado failOn localizado em arquivo de teste → não derruba', async () => {
    const t: Finding = { ...makeFinding('A', 'high'), evidence: 'src/foo.test.ts:3' }
    const orch = makeOrch({ failOn: ['critical', 'high'] })
    orch.registerAgent(makeAgent('A', [t]))

    const report = await orch.scan(target)

    expect(report.passed).toBe(true)
    expect(report.findings.find(x => x.id === t.id)?.confidence).toBe('low')
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

    const orch = makeOrch({ concurrency: 2 })
    orch.registerAgents([slow('A'), slow('B'), slow('C')])

    await orch.scan(target)

    expect(calls.slice(0, 2).sort()).toEqual(['start-A', 'start-B'])
    expect(calls).toContain('end-C')
  })

  it('filters agents based on target.agents allowlist', async () => {
    const a = makeAgent('Keep')
    const b = makeAgent('Drop')
    const orch = makeOrch()
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
    const orch = makeOrch({ concurrency: 2 })
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
    const orch = makeOrch()
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
    const orch = makeOrch()
    orch.registerAgent(hang)

    const report = await orch.scan(target)

    const check = report.checks.find(c => c.agent === 'Hang')
    expect(check?.status).toBe('error')
    expect(check?.motivo).toContain('timeout')
  })

  it('defaults camada and status on findings that omit them', async () => {
    const orch = makeOrch({ failOn: [] })
    orch.registerAgent(makeAgent('A', [makeFinding('A', 'low')]))

    const report = await orch.scan(target)

    expect(report.findings[0].camada).toBe('security')
    expect(report.findings[0].status).toBe('open')
  })

  it('aborts (runs no agents) when a required repo is inaccessible', async () => {
    const a = makeAgent('A', [makeFinding('A', 'high')])
    const orch = new FractaOrchestrator({
      healthCheck: async () => ({ repoAccessible: false, status: 'unreachable' }),
    })
    orch.registerAgent(a)

    const report = await orch.scan({ ...target, repoPath: '/nope/not/a/repo' })

    expect(a.run).not.toHaveBeenCalled()
    expect(report.checks).toHaveLength(0)
    expect(report.passed).toBe(false)
    expect(report.targetHealth.status).toBe('unreachable')
  })

  it('verdict is inconclusive (passed=false) when the target is unreachable and nothing failed', async () => {
    const orch = new FractaOrchestrator({
      healthCheck: async () => ({ repoAccessible: true, stagingResponding: false, status: 'unreachable' }),
      failOn: ['critical', 'high'],
    })
    orch.registerAgent(makeAgent('A', [makeFinding('A', 'low')]))

    const report = await orch.scan(target)

    // Nenhum achado de severidade falha, MAS o alvo não foi alcançado: o único
    // agente que testa a superfície viva nunca rodou → não é "PASSED".
    expect(report.verdict).toBe('inconclusive')
    expect(report.passed).toBe(false)
  })

  it('verdict is failed when a failOn severity is present even if the target is unreachable', async () => {
    const orch = new FractaOrchestrator({
      healthCheck: async () => ({ repoAccessible: true, stagingResponding: false, status: 'unreachable' }),
      failOn: ['critical', 'high'],
    })
    orch.registerAgent(makeAgent('A', [makeFinding('A', 'critical')]))

    const report = await orch.scan(target)

    // Falha real ganha de inconclusivo: há um achado crítico concreto.
    expect(report.verdict).toBe('failed')
    expect(report.passed).toBe(false)
  })

  it('verdict is inconclusive (não "passed") quando um check crasha com erro (#26)', async () => {
    // Um agente carro-chefe que crasha (ex.: url ausente → TypeError) não pode
    // conviver com "✅ PASSOU" no topo: a dimensão dele NÃO foi medida.
    const crasher: SecurityAgent = {
      name: 'HEADERS Agent', category: 'security', concurrency: 1, timeoutMs: 1_000,
      run: async () => { throw new Error("Cannot read properties of undefined (reading 'replace')") },
    }
    const orch = makeOrch({ failOn: ['critical', 'high'] })
    orch.registerAgents([crasher, makeAgent('B', [makeFinding('B', 'low')])])

    const report = await orch.scan(target)

    expect(report.resumo.checksComErro).toContain('HEADERS Agent')
    expect(report.verdict).toBe('inconclusive')
    expect(report.passed).toBe(false)
  })

  it('verdict is passed when healthy and no failOn severity is hit', async () => {
    const orch = makeOrch({ failOn: ['critical', 'high'] })
    orch.registerAgent(makeAgent('A', [makeFinding('A', 'low')]))

    const report = await orch.scan(target)

    expect(report.verdict).toBe('passed')
    expect(report.passed).toBe(true)
  })

  it('passes target health into the agent scope', async () => {
    let seen: TargetHealth | undefined
    const probe: SecurityAgent = {
      name: 'Probe', category: 'security', concurrency: 1, timeoutMs: 1_000,
      run: async scope => { seen = scope.health; return [] },
    }
    const orch = new FractaOrchestrator({
      healthCheck: async () => ({ repoAccessible: true, stagingResponding: true, status: 'healthy' }),
    })
    orch.registerAgent(probe)

    await orch.scan(target)

    expect(seen?.status).toBe('healthy')
    expect(seen?.stagingResponding).toBe(true)
  })
})
