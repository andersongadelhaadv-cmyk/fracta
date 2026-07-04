import { describe, it, expect } from 'vitest'
import { formatVerifyReport } from '../verify-format.js'

describe('formatVerifyReport', () => {
  it('resume o veredito e lista achados', () => {
    const txt = formatVerifyReport({
      url: 'https://exemplo.com',
      verdict: 'ok',
      findings: [{
        id: 'x', runId: 'r', agent: 'Runtime-verify (browser)', category: 'compliance',
        severity: 'low', confidence: 'high',
        title: 'Trackers disparam ANTES do consentimento (confirmado em runtime)',
        description: 'd', recommendation: 'r', createdAt: new Date(),
      }],
      evidence: { trackers: [{ name: 'Meta Pixel (Facebook)', requests: ['x'] }], cookiesSetBeforeConsent: ['_fbp'], cmp: { detected: false }, firedBeforeInteraction: true },
      verifiedAt: '2026-07-03T00:00:00Z',
    })
    expect(txt).toMatch(/Verifica[çc][ãa]o em runtime de https:\/\/exemplo\.com/)
    expect(txt).toMatch(/Meta Pixel/)
    expect(txt).toMatch(/\[low\]/)
  })
})
