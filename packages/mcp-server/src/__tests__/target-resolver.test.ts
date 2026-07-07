import { describe, it, expect } from 'vitest'
import { looksLikeUrl, targetFromUrl } from '../target-resolver.js'
import { assertUsableTarget } from '@fracta/core'

describe('looksLikeUrl', () => {
  it('reconhece http e https (case-insensitive, com espaços)', () => {
    expect(looksLikeUrl('https://exemplo.com.br')).toBe(true)
    expect(looksLikeUrl('http://localhost:3000')).toBe(true)
    expect(looksLikeUrl('  HTTPS://EXEMPLO.com  ')).toBe(true)
  })

  it('rejeita nomes de target configurados e esquemas não-web', () => {
    expect(looksLikeUrl('doutor-inss')).toBe(false)
    expect(looksLikeUrl('file://local')).toBe(false)
    expect(looksLikeUrl('ftp://x')).toBe(false)
    expect(looksLikeUrl('')).toBe(false)
  })
})

describe('targetFromUrl', () => {
  it('constrói um Target ad-hoc read-only nomeado pelo host, escopado ao HEADERS Agent', () => {
    const t = targetFromUrl('https://sub.exemplo.com/rota?x=1')
    expect(t.url).toBe('https://sub.exemplo.com/rota?x=1')
    expect(t.name).toBe('sub.exemplo.com')
    expect(t.stack).toEqual([])
    // não deve lançar — é um alvo DAST utilizável
    expect(() => assertUsableTarget(t)).not.toThrow()
  })

  it('preserva a URL crua e não crasha com host impronunciável', () => {
    const t = targetFromUrl('https://')
    expect(t.url).toBe('https://')
    expect(typeof t.name).toBe('string')
    expect(t.name.length).toBeGreaterThan(0)
  })
})
