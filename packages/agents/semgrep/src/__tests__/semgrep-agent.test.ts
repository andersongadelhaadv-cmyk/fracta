import { describe, it, expect } from 'vitest'
import { SemgrepAgent, type SemgrepRawResult } from '../index.js'
import { SkippedCheck, type ScanScope } from '@fracta/core'

const scope = (repoPath?: string): ScanScope => ({
  target: { name: 'demo', url: 'file://local', stack: [], repoPath },
  depth: 'full', agents: ['SEMGREP Agent'], runId: 'run-1', startedAt: new Date(),
})

const oneResult: SemgrepRawResult = {
  check_id: 'javascript.lang.security.audit.sqli.node-mysql-sqli',
  path: 'src/db.ts', start: { line: 7 },
  extra: { message: 'SQL injection', severity: 'ERROR', metadata: { cwe: ['CWE-89'], confidence: 'HIGH' }, lines: "query('...' + id)" },
}

describe('SemgrepAgent', () => {
  it('roda o scanner injetado e mapeia os resultados em findings', async () => {
    const findings = await new SemgrepAgent(async () => [oneResult]).run(scope('/repo'))
    expect(findings).toHaveLength(1)
    expect(findings[0].location).toEqual({ file: 'src/db.ts', line: 7 })
    expect(findings[0].severity).toBe('high')
  })

  it('SKIP honesto quando falta repoPath (nunca falso-verde)', async () => {
    await expect(new SemgrepAgent(async () => []).run(scope(undefined))).rejects.toBeInstanceOf(SkippedCheck)
  })

  it('propaga o SkippedCheck do scanner (binário ausente)', async () => {
    const skipping: () => Promise<SemgrepRawResult[]> = async () => { throw new SkippedCheck('semgrep ausente') }
    await expect(new SemgrepAgent(skipping).run(scope('/repo'))).rejects.toBeInstanceOf(SkippedCheck)
  })
})
