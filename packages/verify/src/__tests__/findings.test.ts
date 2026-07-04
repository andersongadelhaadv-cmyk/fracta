import { describe, it, expect } from 'vitest'
import { buildVerifyFindings } from '../findings.js'

const base = {
  saas: 'exemplo.com',
  runId: 'run1',
  cookiesBeforeConsent: ['_ga', '_fbp'],
}

describe('buildVerifyFindings', () => {
  it('CONFIRMA violação quando trackers disparam sem CMP', () => {
    const fs = buildVerifyFindings({
      ...base,
      trackers: [{ name: 'Meta Pixel (Facebook)', requests: ['https://www.facebook.com/tr?id=1'] }],
      cmp: { detected: false },
    })
    expect(fs).toHaveLength(1)
    const f = fs[0]
    expect(typeof f.id).toBe('string')
    expect(f.id.length).toBeGreaterThan(0)
    expect(f.severity).toBe('low')
    expect(f.confidence).toBe('high')
    expect(f.agent).toBe('Runtime-verify (browser)')
    expect(f.evidence).toMatch(/facebook\.com\/tr/)
    expect(f.evidence).toMatch(/_fbp/)
    expect(f.description).toMatch(/nenhum CMP/i)
  })

  it('CONFIRMA violação mesmo com CMP presente que NÃO bloqueia', () => {
    const fs = buildVerifyFindings({
      ...base,
      trackers: [{ name: 'Google Analytics 4', requests: ['https://www.google-analytics.com/g/collect'] }],
      cmp: { detected: true, vendor: 'OneTrust' },
    })
    expect(fs).toHaveLength(1)
    expect(fs[0].description).toMatch(/CMP presente.*n[ãa]o bloqueia|não bloqueia/i)
    expect(fs[0].description).toMatch(/OneTrust/)
  })

  it('NÃO acusa violação quando nenhum tracker disparou antes do consentimento', () => {
    const fs = buildVerifyFindings({ ...base, cookiesBeforeConsent: [], trackers: [], cmp: { detected: true, vendor: 'Cookiebot' } })
    expect(fs.some(f => f.severity !== 'info')).toBe(false)
  })
})
