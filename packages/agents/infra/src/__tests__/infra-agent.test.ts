import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { InfraAgent } from '../index.js'
import type { PortProber } from '../index.js'
import { SkippedCheck } from '@fracta/core'
import type { ScanScope, TargetInfra } from '@fracta/core'

// nunca abre socket real: prober injetado, controlado por teste.
const proberNeverOpen: PortProber = async () => false
function proberOpenFor(...openPorts: number[]): PortProber {
  return async (_host, port) => openPorts.includes(port)
}

let tmp: string

function scopeWith(infra?: TargetInfra): ScanScope {
  return {
    target: { name: 'DemoSaaS', url: 'https://demo.test', stack: ['docker'], infra },
    depth: 'full',
    agents: ['INFRA Agent'],
    runId: 'run-1',
    startedAt: new Date(),
  }
}

describe('InfraAgent', () => {
  beforeAll(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'fracta-infra-'))
  })
  afterAll(async () => {
    await rm(tmp, { recursive: true, force: true })
  })

  it('skips when there is no infra at all', async () => {
    await expect(new InfraAgent(proberNeverOpen).run(scopeWith(undefined)))
      .rejects.toBeInstanceOf(SkippedCheck)
  })

  it('skips when infra has none of host/sshConfigPath/dockerComposePath', async () => {
    await expect(new InfraAgent(proberNeverOpen).run(scopeWith({})))
      .rejects.toBeInstanceOf(SkippedCheck)
  })

  it('flags an exposed DB port as critical via the injected prober (5432 open)', async () => {
    const agent = new InfraAgent(proberOpenFor(5432))
    const findings = await agent.run(scopeWith({ host: '203.0.113.10' }))
    const pg = findings.find(f => f.title.includes('5432'))
    expect(pg).toBeDefined()
    expect(pg!.severity).toBe('critical')
    expect(pg!.camada).toBe('infra')
    expect(pg!.proposedFix?.riskOfApplying).toBeTruthy()
    // 6379 estava fechado → não vira finding
    expect(findings.find(f => f.title.includes('6379'))).toBeUndefined()
  })

  it('does NOT flag ports that are closed', async () => {
    const findings = await new InfraAgent(proberNeverOpen).run(scopeWith({ host: '203.0.113.10' }))
    expect(findings).toHaveLength(0)
  })

  it('flags sshd_config missing PasswordAuthentication no and PermitRootLogin no', async () => {
    const sshPath = join(tmp, 'sshd_config')
    await writeFile(sshPath, [
      'Port 22',
      'PasswordAuthentication yes',
      '# PermitRootLogin not set, defaults to allowed',
    ].join('\n'))

    const findings = await new InfraAgent(proberNeverOpen).run(scopeWith({ sshConfigPath: sshPath }))
    const rules = findings.map(f => f.title)
    expect(findings.some(f => f.severity === 'high')).toBe(true)
    expect(rules.some(t => /senha/i.test(t))).toBe(true) // password auth
    expect(rules.some(t => /root/i.test(t))).toBe(true)  // root login
    for (const f of findings) expect(f.proposedFix?.riskOfApplying).toBeTruthy()
  })

  it('does NOT flag a hardened sshd_config', async () => {
    const sshPath = join(tmp, 'sshd_config_hardened')
    await writeFile(sshPath, ['PasswordAuthentication no', 'PermitRootLogin no'].join('\n'))
    const findings = await new InfraAgent(proberNeverOpen).run(scopeWith({ sshConfigPath: sshPath }))
    expect(findings).toHaveLength(0)
  })

  it('flags compose published 5432 + plaintext secret, WITHOUT echoing the secret value', async () => {
    const composePath = join(tmp, 'docker-compose.yml')
    const SECRET_VALUE = 'sup3r-s3cr3t-pg-pass'
    await writeFile(composePath, [
      'services:',
      '  db:',
      '    image: postgres:16',
      '    ports:',
      '      - "5432:5432"',
      '    environment:',
      `      POSTGRES_PASSWORD=${SECRET_VALUE}`,
    ].join('\n'))

    const findings = await new InfraAgent(proberNeverOpen).run(scopeWith({ dockerComposePath: composePath }))

    const published = findings.find(f => f.title.includes('5432'))
    expect(published).toBeDefined()
    expect(published!.severity).toBe('high')

    const secret = findings.find(f => /POSTGRES_PASSWORD/.test(f.title))
    expect(secret).toBeDefined()
    expect(secret!.severity).toBe('high')

    // SANITIZAÇÃO: o valor do segredo NUNCA aparece em nenhum campo do finding.
    const serialized = JSON.stringify(findings)
    expect(serialized).not.toContain(SECRET_VALUE)

    // no-user (low) também esperado (services sem `user:`)
    expect(findings.some(f => f.severity === 'low')).toBe(true)
  })

  it('does NOT flag ${VAR} interpolation as a plaintext secret', async () => {
    const composePath = join(tmp, 'docker-compose-interp.yml')
    await writeFile(composePath, [
      'services:',
      '  api:',
      '    image: app:latest',
      '    user: "1000:1000"',
      '    environment:',
      '      API_KEY=${API_KEY}',
    ].join('\n'))
    const findings = await new InfraAgent(proberNeverOpen).run(scopeWith({ dockerComposePath: composePath }))
    expect(findings.find(f => /API_KEY/.test(f.title))).toBeUndefined()
    expect(findings.find(f => f.title.includes('root'))).toBeUndefined() // tem user:
  })

  it('produces deterministic, infra-tagged ids stable across runs', async () => {
    const agent = new InfraAgent(proberOpenFor(5432, 6379))
    const a = await agent.run(scopeWith({ host: '203.0.113.10' }))
    const b = await agent.run(scopeWith({ host: '203.0.113.10' }))
    expect(a.map(f => f.id)).toEqual(b.map(f => f.id))
    expect(a.every(f => f.camada === 'infra' && f.agent === 'INFRA Agent')).toBe(true)
    expect(new Set(a.map(f => f.id)).size).toBe(a.length)
  })
})
