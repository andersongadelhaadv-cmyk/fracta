import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtemp, readFile, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { FractaReporter } from '../index.js'
import type { AuditReport, Finding } from '@fracta/core'

function finding(partial: Partial<Finding> & Pick<Finding, 'id' | 'title' | 'severity'>): Finding {
  return {
    runId: 'run-1',
    agent: 'headers',
    category: 'security',
    description: 'desc',
    recommendation: 'fix it',
    createdAt: new Date('2026-06-28T12:00:00Z'),
    ...partial,
  }
}

function baseReport(findings: Finding[], extra: Partial<AuditReport> = {}): AuditReport {
  const started = new Date('2026-06-28T12:00:00Z')
  const finished = new Date('2026-06-28T12:00:05Z')
  return {
    runId: 'run-1',
    target: 'DemoSaaS',
    startedAt: started,
    finishedAt: finished,
    durationMs: 5000,
    summary: {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
    },
    findings,
    passed: false,
    saas: 'DemoSaaS',
    timestamp: finished.toISOString(),
    targetHealth: { repoAccessible: true, status: 'healthy' },
    checks: [],
    resumo: {
      porSeveridade: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      regressoes: 0,
      checksComErro: [],
      checksPulados: [],
    },
    ...extra,
  }
}

describe('FractaReporter — Fase 7 (relatório consolidado)', () => {
  let dir: string
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'fracta-reporter-'))
  })
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  async function render(report: AuditReport): Promise<{ md: string; json: AuditReport }> {
    const reporter = new FractaReporter({ outputDir: dir })
    const { mdPath, jsonPath } = await reporter.save(report)
    const md = await readFile(mdPath, 'utf-8')
    const json = JSON.parse(await readFile(jsonPath, 'utf-8')) as AuditReport
    return { md, json }
  }

  it('renders a top "Ação Prioritária" block with critical/high when no LLM order', async () => {
    const report = baseReport([
      finding({ id: 'a', title: 'SQL Injection', severity: 'critical' }),
      finding({ id: 'b', title: 'Missing CSP', severity: 'high' }),
      finding({ id: 'c', title: 'Verbose error', severity: 'low' }),
    ])
    const { md } = await render(report)
    const priorityIdx = md.indexOf('## 🎯 Ação Prioritária')
    expect(priorityIdx).toBeGreaterThan(-1)
    // Critical/high listados; low NÃO entra no topo.
    const block = md.slice(priorityIdx, md.indexOf('## 🔴'))
    expect(block).toContain('SQL Injection')
    expect(block).toContain('Missing CSP')
    expect(block).not.toContain('Verbose error')
    // O topo aparece antes da primeira seção de detalhe por severidade.
    expect(priorityIdx).toBeLessThan(md.indexOf('## 🔴 CRÍTICO'))
  })

  it('honors the LLM prioritization order when present', async () => {
    const report = baseReport(
      [
        finding({ id: 'a', title: 'Low prio bug', severity: 'high' }),
        finding({ id: 'b', title: 'Critical leak', severity: 'critical' }),
      ],
      { prioritization: { order: ['b', 'a'], rationale: 'Vaza dado sensível primeiro.' } },
    )
    const { md } = await render(report)
    const idx = md.indexOf('## 🎯 Ação Prioritária')
    const block = md.slice(idx, md.indexOf('## 🔴'))
    // Ordem do LLM respeitada: 'b' (Critical leak) antes de 'a' (Low prio bug).
    expect(block.indexOf('Critical leak')).toBeLessThan(block.indexOf('Low prio bug'))
    expect(block).toContain('1. ')
    expect(block).toContain('Vaza dado sensível primeiro.')
  })

  it('renders proposedFix (description + command + diff + risk) — gated', async () => {
    const report = baseReport([
      finding({
        id: 'a',
        title: 'No Helmet',
        severity: 'high',
        proposedFix: {
          description: 'Adicionar helmet ao main.ts',
          command: 'npm i helmet',
          diff: '+ app.use(helmet())',
          riskOfApplying: 'Pode quebrar CSP de assets inline.',
        },
      }),
    ])
    const { md } = await render(report)
    expect(md).toContain('Correção proposta (gated')
    expect(md).toContain('Adicionar helmet ao main.ts')
    expect(md).toContain('npm i helmet')
    expect(md).toContain('app.use(helmet())')
    expect(md).toContain('Pode quebrar CSP de assets inline.')
    expect(md).toContain('```diff')
  })

  it('JSON ≡ MD: tudo que o JSON carrega aparece no Markdown', async () => {
    const report = baseReport(
      [
        finding({
          id: 'a',
          title: 'Token vazado',
          severity: 'critical',
          status: 'regression',
          proposedFix: { description: 'rotacionar token', riskOfApplying: 'invalida sessões' },
        }),
      ],
      {
        prioritization: { order: ['a'], rationale: 'Crítico de segredo.' },
        resumo: {
          porSeveridade: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
          regressoes: 1,
          checksComErro: ['idor'],
          checksPulados: ['stripe'],
        },
        checks: [
          { agent: 'idor', camada: 'security', status: 'error', motivo: 'timeout', durationMs: 10, findings: [] },
          { agent: 'stripe', camada: 'security', status: 'skipped', motivo: 'sem stack stripe', durationMs: 1, findings: [] },
        ],
      },
    )
    const { md, json } = await render(report)
    // Cada peça do AuditReport tem reflexo no MD.
    expect(md).toContain(json.findings[0].title)
    expect(md).toContain(json.findings[0].proposedFix!.description)
    expect(md).toContain(json.prioritization!.rationale!)
    expect(md).toContain('Regressões (1)')
    expect(md).toContain('Token vazado')
    // Transparência: checks com erro e pulados declarados com motivo.
    expect(md).toContain('idor')
    expect(md).toContain('timeout')
    expect(md).toContain('stripe')
    expect(md).toContain('sem stack stripe')
  })
})
