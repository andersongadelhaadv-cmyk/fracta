import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ComplianceAgent } from '../index.js'
import { SkippedCheck } from '@fracta/core'
import type { ScanScope } from '@fracta/core'

let repoDir: string

function scopeFor(repoPath?: string): ScanScope {
  return {
    target: { name: 'DemoSaaS', url: 'file://local', stack: ['nestjs'], repoPath },
    depth: 'full',
    agents: ['COMPLIANCE Agent'],
    runId: 'run-1',
    startedAt: new Date(),
  }
}

describe('ComplianceAgent', () => {
  beforeEach(async () => {
    repoDir = await mkdtemp(join(tmpdir(), 'fracta-compliance-'))
  })
  afterEach(async () => {
    await rm(repoDir, { recursive: true, force: true })
  })

  it('skips when there is no repoPath', async () => {
    await expect(new ComplianceAgent().run(scopeFor(undefined)))
      .rejects.toBeInstanceOf(SkippedCheck)
  })

  it('flags sensitive data in a log WITHOUT echoing the logged value', async () => {
    const code = 'export function f(user: any) {\n  console.log(`cpf=${user.cpf}`)\n}\n'
    await writeFile(join(repoDir, 'svc.ts'), code)

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const hit = findings.find(f => f.title.startsWith('Possível dado sensível em log'))
    expect(hit).toBeDefined()
    expect(hit!.severity).toBe('high')
    expect(hit!.camada).toBe('compliance')

    // SANITIZAÇÃO: evidence só tem arquivo:linha + termo, nunca o valor logado.
    expect(hit!.evidence).toContain('svc.ts:2')
    expect(hit!.evidence).toContain('cpf')
    // O valor logado (`user.cpf`) NÃO pode aparecer em lugar nenhum do finding.
    expect(hit!.evidence).not.toContain('user.cpf')
    expect(hit!.evidence).not.toContain('${')
    expect(hit!.description).not.toContain('user.cpf')

    // rule key determinística e id estável.
    const a = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(a.find(f => f.title.startsWith('Possível dado sensível em log'))!.id).toBe(hit!.id)

    // proposedFix sempre com riskOfApplying honesto.
    expect(hit!.proposedFix).toBeDefined()
    expect(hit!.proposedFix!.riskOfApplying).toBeTruthy()
  })

  it('flags password storage without a hashing lib', async () => {
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { '@prisma/client': '^5' } }),
    )
    await writeFile(
      join(repoDir, 'auth.ts'),
      'export async function register(p: string) {\n  return prisma.user.create({ data: { password: p } })\n}\n',
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const hit = findings.find(f => f.title === 'Possível armazenamento de senha sem hashing')
    expect(hit).toBeDefined()
    expect(hit!.severity).toBe('high')
    expect(hit!.proposedFix!.riskOfApplying).toContain('CONFIRMAÇÃO HUMANA')
  })

  it('does NOT flag password storage when bcrypt is present', async () => {
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { bcrypt: '^5' } }),
    )
    await writeFile(
      join(repoDir, 'auth.ts'),
      'export async function register(p: string) {\n  return prisma.user.create({ data: { password: p } })\n}\n',
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings.find(f => f.title === 'Possível armazenamento de senha sem hashing')).toBeUndefined()
  })

  it('flags tenant-isolation in a sensitive file and encryption-unclear, with deterministic rule keys', async () => {
    // arquivo sensível com findMany sem escopo de tenant e sem TLS no repo
    await writeFile(
      join(repoDir, 'repo.ts'),
      'export function list() {\n  // processo de cliente\n  return prisma.processo.findMany({ orderBy: { id: "asc" } })\n}\n',
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))

    const tenant = findings.find(f => f.title.startsWith('Query sem escopo de tenant'))
    expect(tenant).toBeDefined()
    expect(tenant!.severity).toBe('low')

    const enc = findings.find(f => f.title === 'Criptografia em trânsito/repouso não evidenciada')
    expect(enc).toBeDefined()
    expect(enc!.severity).toBe('low')
  })

  it('walks subdirs and ignores node_modules', async () => {
    await mkdir(join(repoDir, 'src'), { recursive: true })
    await mkdir(join(repoDir, 'node_modules', 'pkg'), { recursive: true })
    await writeFile(join(repoDir, 'src', 'deep.ts'), 'logger.info(`token=${t}`)\n')
    await writeFile(join(repoDir, 'node_modules', 'pkg', 'i.ts'), 'console.log(`cpf=${x}`)\n')

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const logs = findings.filter(f => f.title.startsWith('Possível dado sensível em log'))
    expect(logs).toHaveLength(1)
    expect(logs[0].evidence).toContain('src/deep.ts')
    expect(logs[0].evidence).toContain('token')
  })

  it('returns no findings on a clean, non-sensitive repo', async () => {
    await writeFile(join(repoDir, 'index.ts'), 'console.log("hello world")\n')
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings).toHaveLength(0)
  })
})
