import { describe, it, expect } from 'vitest'
import { classifyTrackers } from '../trackers.js'

describe('classifyTrackers', () => {
  it('agrupa requisições por tracker e enxerga o Meta Pixel real', () => {
    const hits = classifyTrackers([
      'https://www.google-analytics.com/g/collect?v=2&tid=G-XXX',
      'https://connect.facebook.net/en_US/fbevents.js',
      'https://www.facebook.com/tr?id=123&ev=PageView',
      'https://example.com/app.js',
    ])
    const names = hits.map(h => h.name)
    expect(names).toContain('Google Analytics 4')
    expect(names).toContain('Meta Pixel (Facebook)')
    const meta = hits.find(h => h.name === 'Meta Pixel (Facebook)')
    expect(meta?.requests.length).toBe(2)
  })

  it('não classifica requisições comuns', () => {
    expect(classifyTrackers(['https://example.com/style.css'])).toEqual([])
  })
})
