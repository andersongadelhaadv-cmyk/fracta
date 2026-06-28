import { describe, it, expect } from 'vitest'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SecretsAgent } from '../index.js'
import type { GitleaksScanner, GitleaksFinding } from '../index.js'
import { SkippedCheck } from '@fracta/core'
import type { ScanScope } from '@fracta/core'

const SECRET_VALUE = 'sk-ant-SUPER-SECRET-VALUE-do-not-leak-123456'

// Dados canned com um campo `Secret`/`Match` (como o gitleaks real produz),
// que NUNCA deve aparecer em nenhum Finding.
const CANNED_LEAKS: Array<GitleaksFinding & { Secret: string; Match: string }> = [
  {
    RuleID: 'anthropic-api-key',
    Description: 'Anthropic API Key',
    File: 'src/config.ts',
    StartLine: 12,
    Commit: 'abcdef1234567890abcdef1234567890abcdef12',
    Date: '2026-01-01T00:00:00Z',
    Author: 'dev@example.test',
    Secret: SECRET_VALUE,
    Match: `ANTHROPIC_API_KEY=${SECRET_VALUE}`,
  },
  {
    RuleID: 'generic-api-key',
    Description: 'Generic',
    File: '.env.backup',
    StartLine: 3,
    Commit: 'fedcba0987654321fedcba0987654321fedcba09',
    Secret: SECRET_VALUE,
    Match: SECRET_VALUE,
  },
]

const scannerWithLeaks: GitleaksScanner = async () => CANNED_LEAKS
const scannerClean: GitleaksScanner = async () => []

function scopeFor(repoPath?: string): ScanScope {
  return {
    target: { name: 'DemoSaaS', url: 'file://local', stack: ['nestjs'], repoPath },
    depth: 'full',
    agents: ['SECRETS Agent'],
    runId: 'run-1',
    startedAt: new Date(),
  }
}

async function makeRepo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fracta-secrets-'))
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content)
  }
  return dir
}

/** Serializa qualquer finding (com Date) para varredura de strings. */
function serialize(findings: unknown): string {
  return JSON.stringify(findings, (_k, v) => (v instanceof Date ? v.toISOString() : v))
}

describe('SecretsAgent', () => {
  it('skips when there is no repoPath', async () => {
    await expect(new SecretsAgent(scannerWithLeaks).run(scopeFor(undefined)))
      .rejects.toBeInstanceOf(SkippedCheck)
  })

  it('maps gitleaks findings and NEVER leaks the secret value', async () => {
    // repo with a proper .gitignore + .env.example so only leak findings appear
    const repo = await makeRepo({
      '.gitignore': 'node_modules\n.env\n',
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(scannerWithLeaks).run(scopeFor(repo))
      const leaks = findings.filter(f => f.title.startsWith('Segredo versionado'))
      expect(leaks).toHaveLength(2)

      // CRITICAL: the secret value never appears anywhere in the findings.
      const dump = serialize(findings)
      expect(dump).not.toContain(SECRET_VALUE)
      expect(dump).not.toContain('Match')

      const anthropic = leaks.find(f => f.title.includes('anthropic-api-key'))!
      expect(anthropic).toBeDefined()
      expect(anthropic.severity).toBe('critical')
      expect(anthropic.title).toContain('src/config.ts')
      expect(anthropic.evidence).toContain('src/config.ts:12')
      expect(anthropic.evidence).toContain('abcdef12') // short commit (8 chars)
      expect(anthropic.evidence).not.toContain(SECRET_VALUE)
      expect(anthropic.proposedFix).toBeDefined()
      expect(anthropic.proposedFix!.riskOfApplying).toBeTruthy()
      expect(anthropic.proposedFix!.command).toBeUndefined() // agent never touches Git
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('flags .env not ignored by an existing .gitignore', async () => {
    const repo = await makeRepo({
      '.gitignore': 'node_modules\ndist\n',
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      const f = findings.find(x => x.title.includes('.env não ignorados'))
      expect(f).toBeDefined()
      expect(f!.severity).toBe('high')
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('does NOT flag when .gitignore already covers .env', async () => {
    const repo = await makeRepo({
      '.gitignore': 'node_modules\n.env*\n',
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      expect(findings.find(x => x.title.includes('.env não ignorados'))).toBeUndefined()
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('flags a missing .env.example (low)', async () => {
    const repo = await makeRepo({ '.gitignore': 'node_modules\n.env\n' })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      const f = findings.find(x => x.title.includes('Sem .env.example'))
      expect(f).toBeDefined()
      expect(f!.severity).toBe('low')
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('flags a .env.example that contains real-looking values (medium)', async () => {
    const repo = await makeRepo({
      '.gitignore': 'node_modules\n.env\n',
      '.env.example': 'API_KEY=sk-ant-realvalue-9f8a7b6c5d4e\nPORT=3000\n',
    })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      const f = findings.find(x => x.title.includes('contém valores reais'))
      expect(f).toBeDefined()
      expect(f!.severity).toBe('medium')
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('does NOT flag a .env.example with only placeholders', async () => {
    const repo = await makeRepo({
      '.gitignore': 'node_modules\n.env\n',
      '.env.example': 'API_KEY=\nDB_URL=<your-db-url>\nDEBUG=true\nHOST=localhost\n',
    })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      expect(findings.find(x => x.title.includes('contém valores reais'))).toBeUndefined()
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('produces deterministic, camada-tagged ids (stable across runs)', async () => {
    const repo = await makeRepo({
      '.gitignore': 'node_modules\ndist\n', // triggers env-not-gitignored too
    })
    try {
      const a = await new SecretsAgent(scannerWithLeaks).run(scopeFor(repo))
      const b = await new SecretsAgent(scannerWithLeaks).run(scopeFor(repo))
      expect(a.map(f => f.id)).toEqual(b.map(f => f.id))
      expect(new Set(a.map(f => f.id)).size).toBe(a.length) // distinct ids
      expect(a.every(f => f.camada === 'secrets')).toBe(true)
      expect(a.every(f => f.category === 'secrets')).toBe(true)
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('skips (not errors) when gitleaks binary is absent', async () => {
    const enoent: GitleaksScanner = async () => {
      throw new SkippedCheck('gitleaks não encontrado no PATH — não foi possível escanear segredos versionados')
    }
    const repo = await makeRepo({ '.gitignore': 'node_modules\n.env\n' })
    try {
      await expect(new SecretsAgent(enoent).run(scopeFor(repo)))
        .rejects.toBeInstanceOf(SkippedCheck)
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })
})
