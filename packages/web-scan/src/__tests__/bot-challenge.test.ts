import { describe, it, expect } from 'vitest'
import { detectBotChallenge } from '../bot-challenge.js'

describe('detectBotChallenge', () => {
  it('detects Cloudflare "Just a moment" JS challenge', () => {
    const r = detectBotChallenge(403, { server: 'cloudflare' }, '<title>Just a moment...</title><div id="challenge-platform"></div>')
    expect(r.challenged).toBe(true)
    expect(r.vendor).toBe('Cloudflare')
  })
  it('detects Cloudflare via cf-mitigated header', () => {
    const r = detectBotChallenge(403, { 'cf-mitigated': 'challenge', server: 'cloudflare' }, '')
    expect(r.challenged).toBe(true)
    expect(r.vendor).toBe('Cloudflare')
  })
  it('detects the managed-challenge body ("enable JavaScript and cookies")', () => {
    const r = detectBotChallenge(503, { server: 'cloudflare' }, 'Please enable JavaScript and cookies to continue')
    expect(r.challenged).toBe(true)
  })
  it('detects Imperva Incapsula', () => {
    expect(detectBotChallenge(200, {}, 'Request unsuccessful. Incapsula incident ID: _incap_123').challenged).toBe(true)
  })
  it('detects DataDome via header', () => {
    expect(detectBotChallenge(403, { 'x-datadome': 'protected' }, '').vendor).toBe('DataDome')
  })
  it('does NOT flag a normal Cloudflare-fronted page (200, real content)', () => {
    const r = detectBotChallenge(200, { server: 'cloudflare' }, '<html><body><a href="/privacidade">Privacidade</a> conteúdo real</body></html>')
    expect(r.challenged).toBe(false)
    expect(r.vendor).toBeNull()
  })
  it('does NOT flag a normal non-CF page', () => {
    expect(detectBotChallenge(200, { server: 'nginx' }, '<html>oi</html>').challenged).toBe(false)
  })
})
