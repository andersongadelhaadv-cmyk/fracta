import { describe, it, expect } from 'vitest'
import { detectStack } from '../detect-stack.js'

describe('detectStack (passivo, conservador)', () => {
  it('detecta Next.js pelo header x-powered-by', () => {
    expect(detectStack({ 'x-powered-by': 'Next.js' }, '')).toContain('nextjs')
  })

  it('detecta Next.js por sinal no HTML (/_next/)', () => {
    const html = '<html><head><link rel="preload" href="/_next/static/chunks/main.js"></head></html>'
    expect(detectStack({}, html)).toContain('nextjs')
  })

  it('detecta Express pelo header x-powered-by', () => {
    expect(detectStack({ 'x-powered-by': 'Express' }, '')).toContain('express')
  })

  it('é case-insensitive na CHAVE do header', () => {
    expect(detectStack({ 'X-Powered-By': 'Next.js' }, '')).toContain('nextjs')
  })

  it('não inventa stack sem sinal forte (fallback neutro = vazio)', () => {
    expect(detectStack({ server: 'nginx' }, '<html><body>oi</body></html>')).toEqual([])
  })

  it('não duplica quando header e HTML apontam o mesmo stack', () => {
    const r = detectStack({ 'x-powered-by': 'Next.js' }, '<script src="/_next/static/x.js"></script>')
    expect(r.filter((s) => s === 'nextjs')).toHaveLength(1)
  })
})
