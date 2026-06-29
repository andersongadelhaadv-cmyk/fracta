import { describe, it, expect } from 'vitest'
import { checkLgpdLite } from '../lgpd-lite.js'

describe('checkLgpdLite', () => {
  it('flags missing privacy-policy link', () => {
    const f = checkLgpdLite('<html><body>oi</body></html>', 'demo', 'run1')
    expect(f.some((x) => x.title.toLowerCase().includes('privacidade'))).toBe(true)
  })
  it('passes when a privacy link is present', () => {
    const html = '<a href="/politica-de-privacidade">Privacidade</a>'
    expect(checkLgpdLite(html, 'demo', 'run1').some((x) => x.title.toLowerCase().includes('privacidade'))).toBe(false)
  })
})
