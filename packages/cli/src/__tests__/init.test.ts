import { describe, it, expect, vi } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { runInit, TARGETS_TEMPLATE, type InitDeps } from '../init.js'

function deps(overrides: Partial<InitDeps> = {}) {
  const write = vi.fn(async (_path: string, _content: string): Promise<void> => {})
  return {
    write,
    deps: { exists: async () => false, write, ...overrides },
  }
}

describe('runInit', () => {
  it('escreve o template quando o arquivo NÃO existe', async () => {
    const { deps: d, write } = deps({ exists: async () => false })
    const r = await runInit({ path: './configs/targets.yaml', force: false }, d)
    expect(r.wrote).toBe(true)
    expect(r.ok).toBe(true)
    expect(write).toHaveBeenCalledWith('./configs/targets.yaml', TARGETS_TEMPLATE)
  })

  it('RECUSA sobrescrever um arquivo existente sem --force (e não escreve)', async () => {
    const { deps: d, write } = deps({ exists: async () => true })
    const r = await runInit({ path: './configs/targets.yaml', force: false }, d)
    expect(r.wrote).toBe(false)
    expect(r.ok).toBe(false)
    expect(r.message).toMatch(/--force/)
    expect(write).not.toHaveBeenCalled()
  })

  it('sobrescreve quando existe E --force', async () => {
    const { deps: d, write } = deps({ exists: async () => true })
    const r = await runInit({ path: './configs/targets.yaml', force: true }, d)
    expect(r.wrote).toBe(true)
    expect(write).toHaveBeenCalledOnce()
  })

  it('o template é YAML válido com a chave `targets`', () => {
    const parsed = parseYaml(TARGETS_TEMPLATE) as { targets?: Record<string, unknown> }
    expect(parsed.targets).toBeTypeOf('object')
    expect(Object.keys(parsed.targets ?? {}).length).toBeGreaterThan(0)
  })
})
