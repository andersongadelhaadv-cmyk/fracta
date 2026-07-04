import { describe, it, expect } from 'vitest'
import { RuntimeVerifier } from '../verifier.js'
import { BrowserUnavailableError } from '../errors.js'

describe('RuntimeVerifier degradação', () => {
  it('lança BrowserUnavailableError quando o loader do browser falha', async () => {
    const v = new RuntimeVerifier({
      loadBrowser: async () => { throw new Error('Cannot find module playwright') },
    })
    await expect(v.verifyConsent('https://example.com')).rejects.toBeInstanceOf(BrowserUnavailableError)
  })
})
