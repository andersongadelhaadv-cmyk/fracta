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

describe('higiene do repositório público (#27)', () => {
  const root = repoRoot()
  const files = trackedFiles(root)

  it('nenhum IP da VPS da frota está hardcoded em arquivo versionado', () => {
    // IP público da VPS compartilhada da frota (recon pronto). Detecção por octetos
    // para não re-vazar o valor literal fora de um único ponto de teste.
    const vpsIp = ['76', '13', '170', '79'].join('.')
    const offenders: string[] = []

    for (const rel of files) {
      // Não se auto-detectar (este arquivo cita o IP de propósito, por octetos).
      if (rel.endsWith('repo-hygiene.test.ts')) continue
      const abs = resolve(root, rel)
      let content: string
      try {
        content = readFileSync(abs, 'utf8')
      } catch {
        continue // binário/ilegível
      }
      if (content.includes(vpsIp)) offenders.push(rel)
    }

    expect(offenders, `IP da VPS vazado em: ${offenders.join(', ')}`).toEqual([])
  })
})
