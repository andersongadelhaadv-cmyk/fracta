import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Guarda de higiene do repositório: uma ferramenta de segurança não pode vazar
 * a topologia da própria infra num repo PÚBLICO. Reproduz o QA 2026-07-02 (🟡-3 / #27):
 * o IP da VPS compartilhada estava hardcoded num prompt versionado.
 *
 * O teste varre APENAS arquivos rastreados pelo Git (o que é público), não o
 * working tree inteiro (evita falsos positivos de node_modules/dist/.git).
 */

const here = dirname(fileURLToPath(import.meta.url))

/** Sobe até achar a raiz do monorepo (pnpm-workspace.yaml). */
function repoRoot(): string {
  let dir = here
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, 'pnpm-workspace.yaml'))) return dir
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  throw new Error('não encontrei a raiz do monorepo (pnpm-workspace.yaml)')
}

function trackedFiles(root: string): string[] {
  return execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' })
    .split(/\r?\n/)
    .filter(Boolean)
}

/**
 * Denylist de valores de INFRA da frota que jamais podem aparecer num repo público
 * (recon pronto para atacante). Detecção por partes para não re-vazar o literal aqui.
 * Adicionar um novo segredo de infra = uma linha nova nesta lista.
 */
const FORBIDDEN_INFRA: Array<{ label: string; value: string }> = [
  { label: 'IP da VPS compartilhada da frota', value: ['76', '13', '170', '79'].join('.') },
]

describe('higiene do repositório público (#27)', () => {
  const root = repoRoot()
  const files = trackedFiles(root)

  // Lê cada arquivo rastreado uma vez (o guard é público = só o que o Git versiona).
  const contents = files
    .filter(rel => !rel.endsWith('repo-hygiene.test.ts')) // não se auto-detectar
    .map(rel => {
      try { return { rel, text: readFileSync(resolve(root, rel), 'utf8') } }
      catch { return null } // binário/ilegível
    })
    .filter((x): x is { rel: string; text: string } => x !== null)

  it.each(FORBIDDEN_INFRA)('não vaza $label em nenhum arquivo versionado', ({ value }) => {
    const offenders = contents.filter(f => f.text.includes(value)).map(f => f.rel)
    expect(offenders, `vazado em: ${offenders.join(', ')}`).toEqual([])
  })
})
