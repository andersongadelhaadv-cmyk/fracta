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

  it('NÃO flagga a palavra portuguesa "Todos/toda/todas" como TODO (FP pt-BR)', async () => {
    // Repro do 86% FP no Praetori: texto pt-BR comuníssimo, ZERO marcador real.
    await writeFile(
      join(tmp, 'privacidade.md'),
      '# Privacidade\n\nTODOS OS DADOS\n\nTodos os dados dos titulares permanecem no Brasil. ' +
        'Toda e qualquer solicitação é atendida. Todas as bases legais são respeitadas.',
    )

    const findings = await new DocsAgent(tmp).run(scope)

    const todo = findings.find(f => f.title.includes('TODOs'))
    expect(todo).toBeUndefined() // "Todos/toda/todas" ≠ marcador TODO
  })

  it('GUARD DE RECALL: ainda flagga marcadores TODO/FIXME/XXX/HACK reais', async () => {
    await writeFile(join(tmp, 'a.md'), '# A\n\nTODO: implementar isto')
    await writeFile(join(tmp, 'b.md'), '# B\n\n<!-- FIXME: bug conhecido -->')
    await writeFile(join(tmp, 'c.md'), '# C\n\nXXX revisar · HACK temporário')

    const findingsA = await new DocsAgent(tmp).run(scope)
    const todos = findingsA.filter(f => f.title.includes('TODOs'))
    // os três arquivos com marcador real devem ser pegos (recall preservado)
    expect(todos.map(f => f.endpoint).sort()).toEqual(['a.md', 'b.md', 'c.md'])
  })

  it('NÃO conta v0/v1 de PATH de rota (/v1/…) nem semver (v1.2) como referência legada (FP real do zap-api)', async () => {
    await writeFile(
      join(tmp, 'api.md'),
      '# API\n\nGET /v1/instances\nPOST /v1/messages\nGET /v1/status\nDELETE /v1/webhooks\nSDK v1.2.3\n',
    )
    const findings = await new DocsAgent(tmp).run(scope)
    expect(findings.find(f => f.title.includes('versões legadas'))).toBeUndefined()
  })

  it('GUARD DE RECALL: ainda flagga referências reais a v0/v1 em prosa', async () => {
    await writeFile(
      join(tmp, 'legacy.md'),
      '# Migração\n\nA API v1 foi descontinuada. Migre da v1 para a v2. A v0 nem existe mais.\n',
    )
    const findings = await new DocsAgent(tmp).run(scope)
    expect(findings.find(f => f.title.includes('versões legadas'))).toBeDefined()
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
