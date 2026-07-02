import { describe, it, expect } from 'vitest'
import { assertUsableTarget } from '../target-validation.js'
import type { Target } from '../types.js'

function t(partial: Partial<Target>): Target {
  return { name: 'demo', url: '', stack: [], ...partial }
}

describe('assertUsableTarget (#26)', () => {
  it('lança erro claro quando o target não tem url NEM repoPath (typo baseUrl)', () => {
    // Reproduz o achado: targets.yaml com `baseUrl:` em vez de `url:` → url vem undefined.
    const bad = { name: 'demo', stack: [] } as unknown as Target
    expect(() => assertUsableTarget(bad)).toThrow(/url/i)
  })

  it('a mensagem menciona o nome do target e sugere o campo url', () => {
    const bad = { name: 'meu-saas', stack: [] } as unknown as Target
    try {
      assertUsableTarget(bad)
      throw new Error('deveria ter lançado')
    } catch (err) {
      expect(String((err as Error).message)).toContain('meu-saas')
      expect(String((err as Error).message)).toMatch(/url/i)
    }
  })

  it('lança quando url existe mas não é http/https e não há repoPath', () => {
    expect(() => assertUsableTarget(t({ url: 'ftp://x' }))).toThrow(/http/i)
    expect(() => assertUsableTarget(t({ url: 'example.com' }))).toThrow(/http/i)
  })

  it('aceita um target com url http válida', () => {
    expect(() => assertUsableTarget(t({ url: 'https://example.com' }))).not.toThrow()
    expect(() => assertUsableTarget(t({ url: 'http://localhost:3000' }))).not.toThrow()
  })

  it('aceita um target somente-repo (SAST) sem url', () => {
    const repoOnly = { name: 'repo', stack: [], repoPath: '/tmp/repo' } as unknown as Target
    expect(() => assertUsableTarget(repoOnly)).not.toThrow()
  })
})
