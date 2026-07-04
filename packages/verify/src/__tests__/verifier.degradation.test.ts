import { describe, it, expect } from 'vitest'
import { RuntimeVerifier } from '../verifier.js'
import { BrowserUnavailableError } from '../errors.js'

function fakeLoaderGotoThrows() {
  const page = {
    on() {},
    route: async () => {},
    goto: async () => { throw new Error('net::ERR_CONNECTION_REFUSED') },
    evaluate: async () => ({ globals: [], selectorsMatched: [] }),
  }
  const context = { newPage: async () => page, cookies: async () => [] as { name: string }[] }
  const browser = { newContext: async () => context, close: async () => {} }
  return (async () => ({ chromium: { launch: async () => browser } })) as any
}

describe('RuntimeVerifier degradação', () => {
  it('lança BrowserUnavailableError quando o loader do browser falha', async () => {
    const v = new RuntimeVerifier({
      loadBrowser: async () => { throw new Error('Cannot find module playwright') },
    })
    await expect(v.verifyConsent('https://example.com')).rejects.toBeInstanceOf(BrowserUnavailableError)
  })

  it('lança BrowserUnavailableError quando o Chromium não inicia (binário ausente)', async () => {
    const v = new RuntimeVerifier({
      // loader resolve (pacote presente), mas o launch do chromium falha (binário ausente)
      loadBrowser: async () => ({
        chromium: { launch: async () => { throw new Error("browserType.launch: Executable doesn't exist") } },
      }) as any,
    })
    await expect(v.verifyConsent('https://example.com')).rejects.toBeInstanceOf(BrowserUnavailableError)
  })

  it('navegação falha → verdict inconclusive (não lança, nunca verde falso)', async () => {
    const v = new RuntimeVerifier({ allowPrivateForTest: true, loadBrowser: fakeLoaderGotoThrows() })
    const r = await v.verifyConsent('http://127.0.0.1:1')
    expect(r.verdict).toBe('inconclusive')
    expect(r.findings).toEqual([])
  })
})
