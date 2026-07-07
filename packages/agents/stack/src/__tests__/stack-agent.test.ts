import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, writeFile, rm, mkdir } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { StackAgent } from '../index.js'
import { SkippedCheck, stableFindingId } from '@fracta/core'
import type { ScanScope, Target } from '@fracta/core'

// O contrato do Finding NÃO expõe `rule`; ele só vira `id` via stableFindingId.
// Helper para checar presença de um rule de chave fixa (sem :line) pelo id determinístico.
function hasRule(findings: { id: string }[], rule: string, location?: string): boolean {
  const id = stableFindingId({ saas: 'demo', camada: 'code', rule, location })
  return findings.some(f => f.id === id)
}

let tmp: string

function makeScope(repoPath?: string): ScanScope {
  const target: Target = { name: 'demo', url: 'http://example.test', stack: [], repoPath }
  return { target, depth: 'quick', agents: ['STACK Agent'], runId: 'run-1', startedAt: new Date() }
}

async function write(rel: string, content: string): Promise<void> {
  const full = join(tmp, rel)
  const dir = full.slice(0, Math.max(full.lastIndexOf('/'), full.lastIndexOf('\\')))
  await mkdir(dir, { recursive: true })
  await writeFile(full, content)
}

describe('StackAgent', () => {
  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'fracta-stack-'))
  })

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true })
  })

  it('skips when repoPath is missing', async () => {
    await expect(new StackAgent().run(makeScope(undefined))).rejects.toBeInstanceOf(SkippedCheck)
  })

  it('ignora .worktrees/.claude (worktrees) — não duplica achados (#40)', async () => {
    // MESMA chave hardcoded na árvore principal E dentro de worktrees.
    await write('src/pay.ts', 'const k = "sk_live_ABCDEF123456"\n')
    await write('.worktrees/wt-a/src/pay.ts', 'const k = "sk_live_ABCDEF123456"\n')
    await write('.claude/worktrees/wt-b/src/pay.ts', 'const k = "sk_live_ABCDEF123456"\n')

    const findings = await new StackAgent().run(makeScope(tmp))
    const keys = findings.filter(f => /Chave de provider hardcoded/.test(f.title))
    // Só a ocorrência da árvore principal — worktrees ignorados.
    expect(keys).toHaveLength(1)
    expect(keys[0].evidence).toContain('src/pay.ts:1')
    expect(keys.some(f => /worktrees/.test(f.evidence ?? ''))).toBe(false)
  })

  it('flags helmet missing, validationpipe missing and throttler missing for a NestJS app', async () => {
    await write('package.json', JSON.stringify({ dependencies: { '@nestjs/core': '^10.0.0' } }))
    await write('src/main.ts', [
      "import { NestFactory } from '@nestjs/core'",
      'async function bootstrap() {',
      '  const app = await NestFactory.create(AppModule)',
      '  await app.listen(3000)',
      '}',
      'bootstrap()',
    ].join('\n'))

    const findings = await new StackAgent().run(makeScope(tmp))

    expect(hasRule(findings, 'helmet-missing')).toBe(true)
    expect(hasRule(findings, 'validationpipe-missing')).toBe(true)
    expect(hasRule(findings, 'throttler-missing')).toBe(true)

    const helmet = findings.find(f => f.title.includes('Helmet'))!
    expect(helmet.severity).toBe('medium')
    expect(helmet.proposedFix?.riskOfApplying).toBeTruthy()
  })

  it('does NOT flag helmet/validationpipe when present and configured', async () => {
    await write('package.json', JSON.stringify({
      dependencies: { '@nestjs/core': '^10.0.0', '@nestjs/throttler': '^5.0.0' },
    }))
    await write('src/main.ts', [
      "import helmet from 'helmet'",
      "import { ValidationPipe } from '@nestjs/common'",
      'async function bootstrap() {',
      '  const app = await NestFactory.create(AppModule)',
      '  app.use(helmet())',
      '  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))',
      '  await app.listen(3000)',
      '}',
    ].join('\n'))

    const findings = await new StackAgent().run(makeScope(tmp))

    expect(hasRule(findings, 'helmet-missing')).toBe(false)
    expect(hasRule(findings, 'validationpipe-missing')).toBe(false)
    expect(hasRule(findings, 'validationpipe-no-whitelist', 'src/main.ts')).toBe(false)
    expect(hasRule(findings, 'throttler-missing')).toBe(false)
  })

  it('flags validationpipe-no-whitelist when used without whitelist', async () => {
    await write('package.json', JSON.stringify({ dependencies: { '@nestjs/core': '^10' } }))
    await write('src/main.ts', [
      'async function bootstrap() {',
      '  const app = await NestFactory.create(AppModule)',
      '  app.useGlobalPipes(new ValidationPipe({ transform: true }))',
      '}',
    ].join('\n'))

    const findings = await new StackAgent().run(makeScope(tmp))
    expect(hasRule(findings, 'validationpipe-no-whitelist', 'src/main.ts')).toBe(true)
    const f = findings.find(x => x.title.includes('whitelist'))
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.location).toEqual({ file: 'src/main.ts', line: 3 })
  })

  it('flags raw SQL via $queryRawUnsafe and concatenation but NOT safe tagged templates', async () => {
    await write('src/db.ts', [
      "const a = prisma.$queryRawUnsafe('SELECT * FROM users WHERE id = ' + id)",
      'const b = prisma.$executeRaw(`DELETE FROM t WHERE x = ${val}`)',
      'const safe = prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`',
    ].join('\n'))

    const findings = await new StackAgent().run(makeScope(tmp))
    const sqlFindings = findings.filter(f => f.title.startsWith('Risco de SQL injection'))

    expect(sqlFindings.length).toBe(2)
    expect(sqlFindings.every(f => f.severity === 'high')).toBe(true)
    // a forma segura (tagged template) não deve aparecer
    expect(sqlFindings.some(f => f.evidence?.includes('$queryRaw`'))).toBe(false)
    // localização ESTRUTURADA → SARIF region.startLine (âncora inline no GitHub)
    const first = sqlFindings.find(f => f.location?.line === 1)!
    expect(first.location).toEqual({ file: 'src/db.ts', line: 1 })
    expect(sqlFindings.every(f => f.location?.file === 'src/db.ts' && (f.location?.line ?? 0) > 0)).toBe(true)
    // CWE → alimenta o scorecard OWASP (SQLi = CWE-89 → A03)
    expect(first.references?.some(r => /definitions\/89\b/.test(r))).toBe(true)
  })

  it('flags NEXT_PUBLIC_ secret in .env and masks nothing of the value', async () => {
    await write('.env', 'NEXT_PUBLIC_API_SECRET=super-secret-value\nNEXT_PUBLIC_SITE_URL=https://x.com')

    const findings = await new StackAgent().run(makeScope(tmp))
    expect(hasRule(findings, 'next-public-secret:NEXT_PUBLIC_API_SECRET', '.env')).toBe(true)
    const f = findings.find(x => x.title.includes('NEXT_PUBLIC_API_SECRET'))

    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    // não vaza o valor do segredo
    expect(f!.evidence).not.toContain('super-secret-value')
    expect(f!.location).toEqual({ file: '.env', line: 1 })
    // variável "benigna" (sem KEY/SECRET/etc no nome) não vira finding
    expect(hasRule(findings, 'next-public-secret:NEXT_PUBLIC_SITE_URL', '.env')).toBe(false)
  })

  it('flags CORS wildcard origin', async () => {
    await write('src/cors.ts', "app.enableCors({ origin: '*', credentials: true })")

    const findings = await new StackAgent().run(makeScope(tmp))
    const f = findings.find(x => x.title.startsWith('CORS permissivo'))

    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.location).toEqual({ file: 'src/cors.ts', line: 1 })
    expect(f!.references?.some(r => /definitions\/942\b/.test(r))).toBe(true) // → A05
  })

  it('flags hardcoded provider key and MASKS it in evidence', async () => {
    const fullKey = 'sk_live_ABCDEF1234567890abcdef'
    await write('src/payments.ts', `const stripe = new Stripe('${fullKey}')`)

    const findings = await new StackAgent().run(makeScope(tmp))
    const f = findings.find(x => x.title.startsWith('Chave de provider hardcoded'))

    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    // chave mascarada: só prefixo + reticências, nunca a chave inteira
    expect(f!.evidence).not.toContain(fullKey)
    expect(f!.evidence).toContain('sk_live')
    expect(f!.evidence).toContain('…')
    expect(f!.location).toEqual({ file: 'src/payments.ts', line: 1 })
    expect(f!.references?.some(r => /definitions\/798\b/.test(r))).toBe(true) // → A07
  })

  it('flags tenant-isolation heuristic for findMany without tenant scoping', async () => {
    await write('src/repo.ts', 'const rows = await prisma.user.findMany({ where: { active: true } })')

    const findings = await new StackAgent().run(makeScope(tmp))
    const f = findings.find(x => x.title.startsWith('Possível falta de isolamento de tenant'))

    expect(f).toBeDefined()
    expect(f!.severity).toBe('low')
    expect(f!.description.toLowerCase()).toContain('heur')
    expect(f!.location).toEqual({ file: 'src/repo.ts', line: 1 })
  })

  it('does NOT flag tenant heuristic when tenantId is in the where', async () => {
    await write('src/repo.ts', 'const rows = await prisma.user.findMany({ where: { tenantId: ctx.tenantId } })')

    const findings = await new StackAgent().run(makeScope(tmp))
    expect(findings.some(x => x.title.startsWith('Possível falta de isolamento de tenant'))).toBe(false)
  })

  it('produces stable ids and required Finding shape', async () => {
    await write('src/db.ts', "prisma.$queryRawUnsafe('x' + y)")
    const a = await new StackAgent().run(makeScope(tmp))
    const b = await new StackAgent().run(makeScope(tmp))
    expect(a[0].id).toBe(b[0].id)
    expect(a[0].agent).toBe('STACK Agent')
    expect(a[0].category).toBe('code')
    expect(a[0].camada).toBe('code')
    expect(a[0].runId).toBe('run-1')
    expect(a[0].createdAt).toBeInstanceOf(Date)
  })
})
