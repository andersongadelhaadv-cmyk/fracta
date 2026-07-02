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

  it('flags a committed .env when .gitignore is absent (high)', async () => {
    // Worst-case: no .gitignore at all + a .env file present in the repo root.
    const repo = await makeRepo({
      '.env': 'API_KEY=sk-ant-SUPER-SECRET-12345\nDB_URL=postgres://prod:pw@host/db\n',
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      const f = findings.find(x => x.title.includes('sem .gitignore'))
      expect(f).toBeDefined()
      expect(f!.severity).toBe('high')
      // stableFindingId returns a hex hash — verify it is a non-empty stable string.
      expect(f!.id).toMatch(/^[0-9a-f]+$/)
      // Must NOT re-expose any secret value from the .env
      const dump = serialize(findings)
      expect(dump).not.toContain('sk-ant-SUPER-SECRET-12345')
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('does NOT flag no-gitignore-with-env when .gitignore exists and covers .env', async () => {
    // A repo with a proper .gitignore should NOT trigger the absent-gitignore finding.
    const repo = await makeRepo({
      '.gitignore': 'node_modules\n.env\n.env.*\n',
      '.env': 'API_KEY=sk-ant-SUPER-SECRET-99999\n',
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      expect(findings.find(x => x.title.includes('sem .gitignore'))).toBeUndefined()
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('does NOT flag no-gitignore-with-env when .gitignore is absent but no .env present', async () => {
    // No .gitignore but no .env file either → no finding for this rule.
    const repo = await makeRepo({
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(scannerClean).run(scopeFor(repo))
      expect(findings.find(x => x.title.includes('sem .gitignore'))).toBeUndefined()
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  // Scanner que simula o gitleaks AUSENTE do PATH (estado default no Windows/npx).
  const gitleaksAbsent: GitleaksScanner = async () => {
    throw new SkippedCheck('gitleaks não encontrado no PATH — não foi possível escanear segredos versionados')
  }

  it('AINDA roda a higiene (rede de segurança) quando o gitleaks está ausente (#25)', async () => {
    // Pior caso e mais comum: dev sem gitleaks, repo com .env versionado SEM .gitignore.
    // Antes do fix, o SkippedCheck do gitleaks abortava o run() e a higiene nunca rodava.
    const repo = await makeRepo({
      '.env': 'API_KEY=sk-ant-SUPER-SECRET-12345\nDB_URL=postgres://prod:pw@host/db\n',
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(gitleaksAbsent).run(scopeFor(repo))
      const hygiene = findings.find(x => x.title.includes('sem .gitignore'))
      expect(hygiene, 'a higiene deve rodar mesmo sem gitleaks').toBeDefined()
      expect(hygiene!.severity).toBe('high')
      // Não re-expõe o segredo do .env.
      expect(serialize(findings)).not.toContain('sk-ant-SUPER-SECRET-12345')
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('emite um finding INFO honesto de que o gitleaks não rodou (ausência ≠ seguro) (#25)', async () => {
    const repo = await makeRepo({
      '.env': 'API_KEY=x\n', // higiene tem algo a dizer
      '.env.example': 'API_KEY=\n',
    })
    try {
      const findings = await new SecretsAgent(gitleaksAbsent).run(scopeFor(repo))
      const skipNote = findings.find(x => x.severity === 'info' && /gitleaks/i.test(x.title))
      expect(skipNote, 'deve registrar que segredos versionados NÃO foram escaneados').toBeDefined()
      expect(skipNote!.description.toLowerCase()).toContain('não')
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })

  it('quando o gitleaks está ausente E a higiene está limpa, pula honestamente (preserva #8)', async () => {
    // Nada a reportar: gitignore cobre .env, .env.example placeholder, sem .env versionado.
    // Sem findings de higiene → mantém o SkippedCheck honesto (SECRETS aparece como "não rodou").
    const repo = await makeRepo({
      '.gitignore': 'node_modules\n.env\n.env.*\n',
      '.env.example': 'API_KEY=\n',
    })
    try {
      await expect(new SecretsAgent(gitleaksAbsent).run(scopeFor(repo)))
        .rejects.toBeInstanceOf(SkippedCheck)
      // O skip do gitleaks é DEGRADADO (capacidade faltando), não benigno: o topo
      // do relatório deve virar "COM RESSALVAS", não um verde limpo (🧭-A).
      await new SecretsAgent(gitleaksAbsent).run(scopeFor(repo)).catch((err: unknown) => {
        expect(err).toBeInstanceOf(SkippedCheck)
        expect((err as SkippedCheck).degraded).toBe(true)
      })
    } finally {
      await rm(repo, { recursive: true, force: true })
    }
  })
})
