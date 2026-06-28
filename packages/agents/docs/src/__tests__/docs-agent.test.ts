import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, writeFile, rm, utimes } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { DocsAgent } from '../index.js'
import { SkippedCheck } from '@fracta/core'
import type { ScanScope } from '@fracta/core'

let tmp: string

const scope: ScanScope = {
  target: { name: 'demo', url: 'http://example.test', stack: [] },
  depth: 'quick',
  agents: ['DOCS Agent'],
  runId: 'run-1',
  startedAt: new Date(),
}

describe('DocsAgent', () => {
  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'fracta-docs-'))
  })

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true })
  })

  it('flags TODO markers and stale docs', async () => {
    const stale = join(tmp, 'old.md')
    await writeFile(stale, '# Title\n\nTODO: revisit this section')
    const oldDate = new Date(Date.now() - 365 * 86_400_000)
    await utimes(stale, oldDate, oldDate)

    const findings = await new DocsAgent(tmp).run(scope)

    const todo = findings.find(f => f.title.includes('TODOs'))
    const obsolete = findings.find(f => f.title.includes('obsoleta'))
    expect(todo).toBeDefined()
    expect(obsolete).toBeDefined()
  })

  it('flags duplicate H1 titles across files', async () => {
    await writeFile(join(tmp, 'a.md'), '# Setup\n\nA')
    await writeFile(join(tmp, 'b.md'), '# Setup\n\nB')

    const findings = await new DocsAgent(tmp).run(scope)

    const dup = findings.find(f => f.title.includes('duplicado'))
    expect(dup).toBeDefined()
  })

  it('skips (SkippedCheck) when neither an explicit path nor target.repoPath is given', async () => {
    // Sem repoPath o agente NÃO pode cair no cwd (escanearia o próprio Fracta):
    // "não verificado" ≠ "seguro" → vira skipped.
    await expect(new DocsAgent().run(scope)).rejects.toBeInstanceOf(SkippedCheck)
  })

  it('audits target.repoPath when no explicit path is passed', async () => {
    await writeFile(join(tmp, 'only-in-tmp.md'), '# Title\n\nTODO: fix this')
    const scoped: ScanScope = { ...scope, target: { ...scope.target, repoPath: tmp } }

    const findings = await new DocsAgent().run(scoped)

    // Discriminante: o achado tem de ser do arquivo DENTRO de target.repoPath
    // (endpoint relativo a tmp), provando que NÃO caiu no cwd.
    const todo = findings.find(f => f.endpoint === 'only-in-tmp.md')
    expect(todo).toBeDefined()
    expect(todo!.title).toContain('TODOs')
  })
})
