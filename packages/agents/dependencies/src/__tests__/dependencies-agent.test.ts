import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DependenciesAgent } from '../index.js'
import { SkippedCheck } from '@fracta/core'
import type { ScanScope, CommandResult, CommandRunner } from '@fracta/core'

const CANNED_AUDIT = {
  vulnerabilities: {
    lodash: {
      name: 'lodash', severity: 'high', range: '<4.17.21',
      via: [{ title: 'Prototype Pollution', url: 'https://example.test/adv' }],
      fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
    },
    minimist: {
      name: 'minimist', severity: 'critical', range: '<1.2.6',
      via: ['minimist'], fixAvailable: true,
    },
    'old-pkg': {
      name: 'old-pkg', severity: 'moderate', range: '*', via: [], fixAvailable: false,
    },
  },
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 1, high: 1, critical: 1, total: 3 } },
}

const runnerOk: CommandRunner = async () =>
  ({ stdout: JSON.stringify(CANNED_AUDIT), stderr: '', code: 1 }) satisfies CommandResult

let repoDir: string

function scopeFor(repoPath?: string): ScanScope {
  return {
    target: { name: 'DemoSaaS', url: 'file://local', stack: ['nestjs'], repoPath },
    depth: 'full',
    agents: ['DEPENDENCIES Agent'],
    runId: 'run-1',
    startedAt: new Date(),
  }
}

describe('DependenciesAgent', () => {
  beforeAll(async () => {
    repoDir = await mkdtemp(join(tmpdir(), 'fracta-deps-'))
    await writeFile(join(repoDir, 'package.json'), JSON.stringify({ name: 'demo' }))
  })
  afterAll(async () => {
    await rm(repoDir, { recursive: true, force: true })
  })

  it('skips when there is no repoPath', async () => {
    await expect(new DependenciesAgent(runnerOk).run(scopeFor(undefined)))
      .rejects.toBeInstanceOf(SkippedCheck)
  })

  it('skips when repoPath has no package.json', async () => {
    const empty = await mkdtemp(join(tmpdir(), 'fracta-empty-'))
    try {
      await expect(new DependenciesAgent(runnerOk).run(scopeFor(empty)))
        .rejects.toBeInstanceOf(SkippedCheck)
    } finally {
      await rm(empty, { recursive: true, force: true })
    }
  })

  it('maps npm severities to Fracta severities', async () => {
    const findings = await new DependenciesAgent(runnerOk).run(scopeFor(repoDir))
    const byPkg = Object.fromEntries(findings.map(f => [f.title.split(':')[1]?.trim().split(' ')[0], f.severity]))
    expect(findings).toHaveLength(3)
    expect(byPkg['lodash']).toBe('high')
    expect(byPkg['minimist']).toBe('critical')
    expect(byPkg['old-pkg']).toBe('medium') // moderate → medium
  })

  it('produces gated proposedFix with riskOfApplying for each finding', async () => {
    const findings = await new DependenciesAgent(runnerOk).run(scopeFor(repoDir))
    for (const f of findings) {
      expect(f.proposedFix).toBeDefined()
      expect(f.proposedFix!.riskOfApplying).toBeTruthy()
    }
    const minimist = findings.find(f => f.title.includes('minimist'))!
    expect(minimist.proposedFix!.command).toBe('npm audit fix')
    const lodash = findings.find(f => f.title.includes('lodash'))!
    expect(lodash.proposedFix!.command).toContain('npm install lodash@4.17.21')
    const oldPkg = findings.find(f => f.title.includes('old-pkg'))!
    expect(oldPkg.proposedFix!.command).toBeUndefined() // sem fix automático
  })

  it('produces deterministic, camada-tagged ids (stable across runs)', async () => {
    const a = await new DependenciesAgent(runnerOk).run(scopeFor(repoDir))
    const b = await new DependenciesAgent(runnerOk).run(scopeFor(repoDir))
    expect(a.map(f => f.id)).toEqual(b.map(f => f.id))
    expect(new Set(a.map(f => f.id)).size).toBe(a.length) // ids distintos entre achados
    expect(a.every(f => f.camada === 'deps')).toBe(true)
  })

  it('skips (not errors) when npm is not installed', async () => {
    const enoent: CommandRunner = async () => {
      throw Object.assign(new Error('spawn npm ENOENT'), { code: 'ENOENT' })
    }
    await expect(new DependenciesAgent(enoent).run(scopeFor(repoDir)))
      .rejects.toBeInstanceOf(SkippedCheck)
  })

  it('skips when there is no lockfile (unparseable audit output)', async () => {
    const noLock: CommandRunner = async () =>
      ({ stdout: 'npm error', stderr: 'This command requires an existing lockfile.', code: 1 })
    await expect(new DependenciesAgent(noLock).run(scopeFor(repoDir)))
      .rejects.toBeInstanceOf(SkippedCheck)
  })
})
