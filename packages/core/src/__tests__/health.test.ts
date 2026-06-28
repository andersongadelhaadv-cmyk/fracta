import { describe, it, expect } from 'vitest'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { checkTargetHealth, deriveHealthStatus } from '../health.js'
import type { Target } from '../types.js'

describe('deriveHealthStatus', () => {
  it('is unreachable when a required repo is inaccessible', () => {
    expect(deriveHealthStatus({
      hasRepo: true, repoAccessible: false,
      stagingApplicable: false, vpsApplicable: false,
    })).toBe('unreachable')
  })

  it('is healthy when there is nothing external to probe (repo-only, repo ok)', () => {
    expect(deriveHealthStatus({
      hasRepo: true, repoAccessible: true,
      stagingApplicable: false, vpsApplicable: false,
    })).toBe('healthy')
  })

  it('is healthy when every applicable probe responds', () => {
    expect(deriveHealthStatus({
      hasRepo: false, repoAccessible: true,
      stagingApplicable: true, stagingResponding: true,
      vpsApplicable: true, vpsReachable: true,
    })).toBe('healthy')
  })

  it('is degraded when some probes respond and others do not', () => {
    expect(deriveHealthStatus({
      hasRepo: false, repoAccessible: true,
      stagingApplicable: true, stagingResponding: true,
      vpsApplicable: true, vpsReachable: false,
    })).toBe('degraded')
  })

  it('is unreachable when all applicable probes fail', () => {
    expect(deriveHealthStatus({
      hasRepo: false, repoAccessible: true,
      stagingApplicable: true, stagingResponding: false,
      vpsApplicable: false,
    })).toBe('unreachable')
  })
})

describe('checkTargetHealth (repo)', () => {
  const base = (overrides: Partial<Target>): Target => ({
    name: 'x', url: 'file://local', stack: [], ...overrides,
  })

  it('marks a directory with a .git entry as accessible', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fracta-health-'))
    await writeFile(join(dir, '.git'), 'gitdir: irrelevant') // .git pode ser arquivo (worktree)
    try {
      const health = await checkTargetHealth(base({ repoPath: dir }))
      expect(health.repoAccessible).toBe(true)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('marks a non-existent path as inaccessible and unreachable', async () => {
    const health = await checkTargetHealth(base({ repoPath: '/definitely/not/here/xyz' }))
    expect(health.repoAccessible).toBe(false)
    expect(health.status).toBe('unreachable')
  })

  it('does not probe staging for non-http urls', async () => {
    const health = await checkTargetHealth(base({ url: 'file://local' }))
    expect(health.stagingResponding).toBeUndefined()
  })
})
