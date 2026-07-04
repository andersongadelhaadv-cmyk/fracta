import { describe, it, expect } from 'vitest'
import { detectCmp } from '../cmp.js'

describe('detectCmp', () => {
  it('detecta CMP conhecido por global (OneTrust)', () => {
    const r = detectCmp({ globals: ['OneTrust'], selectorsMatched: [] })
    expect(r.detected).toBe(true)
    expect(r.vendor).toBe('OneTrust')
  })

  it('detecta CMP por seletor de banner (Cookiebot)', () => {
    const r = detectCmp({ globals: [], selectorsMatched: ['#CybotCookiebotDialog'] })
    expect(r.detected).toBe(true)
    expect(r.vendor).toBe('Cookiebot')
  })

  it('não detecta CMP quando não há sinais fortes', () => {
    expect(detectCmp({ globals: ['jQuery'], selectorsMatched: [] }).detected).toBe(false)
  })
})
