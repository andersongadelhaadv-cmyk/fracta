import { describe, it, expect } from 'vitest'
import { FractaHttpClient } from '../http-client.js'
import { SkippedCheck } from '../types.js'

describe('FractaHttpClient — url ausente (#26)', () => {
  it('lança SkippedCheck (não TypeError cru) quando baseUrl é undefined', () => {
    // Antes: `baseUrl.replace(...)` → "Cannot read properties of undefined (reading 'replace')".
    // Agora: skip honesto → o orquestrador marca o check como "não rodou", nunca crash cru.
    expect(() => new FractaHttpClient(undefined as unknown as string))
      .toThrow(SkippedCheck)
  })

  it('lança SkippedCheck quando baseUrl é string vazia', () => {
    expect(() => new FractaHttpClient('')).toThrow(SkippedCheck)
  })

  it('constrói normalmente com uma url válida', () => {
    expect(() => new FractaHttpClient('https://example.com/')).not.toThrow()
  })
})
