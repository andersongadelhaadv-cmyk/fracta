import { describe, it, expect } from 'vitest'
import { launchWithFallback } from '../verifier.js'
import { BrowserUnavailableError } from '../errors.js'

describe('launchWithFallback', () => {
  it('usa o Chromium default quando disponível', async () => {
    const calls: Array<{ headless: boolean; channel?: string }> = []
    const chromium = { launch: async (o: { headless: boolean; channel?: string }) => { calls.push(o); return { tag: 'default' } as any } }
    const b = await launchWithFallback(chromium)
    expect((b as any).tag).toBe('default')
    expect(calls).toHaveLength(1)
    expect(calls[0].channel).toBeUndefined()
  })
  it('cai pro Chrome do sistema (channel:chrome) quando o default falha', async () => {
    const calls: Array<{ headless: boolean; channel?: string }> = []
    const chromium = { launch: async (o: { headless: boolean; channel?: string }) => {
      calls.push(o)
      if (!o.channel) throw new Error('no default browser installed')
      return { tag: 'system-chrome' } as any
    } }
    const b = await launchWithFallback(chromium)
    expect((b as any).tag).toBe('system-chrome')
    expect(calls).toHaveLength(2)
    expect(calls[1].channel).toBe('chrome')
  })
  it('ambos falham → BrowserUnavailableError com mensagem acionável', async () => {
    const chromium = { launch: async () => { throw new Error('nope') } }
    await expect(launchWithFallback(chromium)).rejects.toBeInstanceOf(BrowserUnavailableError)
  })
})
