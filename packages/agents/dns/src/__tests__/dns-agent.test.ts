import { describe, it, expect } from 'vitest'
import type { ScanScope } from '@fracta/core'
import { DnsAgent, parseSpf, parseDmarc, registrableDomain, analyzeEmailDns, type DnsResolver } from '../index.js'

function scopeFor(url: string): ScanScope {
  return { target: { name: 'Demo', url, stack: [] }, depth: 'full', agents: ['DNS Agent'], runId: 'r1', startedAt: new Date() }
}

function mock(txt: Record<string, string[][]>, mx: Record<string, Array<{ exchange: string; priority: number }>> = {}): DnsResolver {
  const nf = () => Promise.reject(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }))
  return {
    resolveTxt: (n) => (n in txt ? Promise.resolve(txt[n]) : nf()),
    resolveMx: (n) => (n in mx ? Promise.resolve(mx[n]) : nf()),
  }
}

describe('parsers', () => {
  it('parseSpf lê o qualifier do all', () => {
    expect(parseSpf([['v=spf1 include:_spf.google.com -all']]).all).toBe('fail')
    expect(parseSpf([['v=spf1 +all']]).all).toBe('pass')
    expect(parseSpf([['v=spf1 ?all']]).all).toBe('neutral')
    expect(parseSpf([['not spf']]).present).toBe(false)
  })
  it('parseSpf junta TXT em chunks', () => {
    expect(parseSpf([['v=spf1 include:a ', 'include:b -all']]).all).toBe('fail')
  })
  it('parseDmarc lê a policy', () => {
    expect(parseDmarc([['v=DMARC1; p=reject; rua=mailto:x@y']]).policy).toBe('reject')
    expect(parseDmarc([['v=DMARC1; p=none']]).policy).toBe('none')
    expect(parseDmarc([['nada']]).present).toBe(false)
  })
})

describe('registrableDomain', () => {
  it('resolve eTLD+1 (inclui .com.br) e tira www', () => {
    expect(registrableDomain('www.advocus.com.br')).toBe('advocus.com.br')
    expect(registrableDomain('app.pleita.pro')).toBe('pleita.pro')
    expect(registrableDomain('fracta.pro')).toBe('fracta.pro')
    expect(registrableDomain('mail.veredicto.tech')).toBe('veredicto.tech')
  })
})

describe('DnsAgent', () => {
  it('SPF/DMARC ausentes: medium COM MX, low SEM MX (confiança alta)', async () => {
    const withMx = await new DnsAgent(mock({}, { 'exemplo.com': [{ exchange: 'mx', priority: 10 }] })).run(scopeFor('https://exemplo.com'))
    expect(withMx.find(f => f.title.startsWith('Sem registro SPF'))?.severity).toBe('medium')
    expect(withMx.find(f => f.title.startsWith('Sem registro DMARC'))?.severity).toBe('medium')
    expect(withMx.find(f => f.title.startsWith('Sem registro SPF'))?.confidence).toBe('high')

    const noMx = await new DnsAgent(mock({})).run(scopeFor('https://exemplo.com'))
    expect(noMx.find(f => f.title.startsWith('Sem registro SPF'))?.severity).toBe('low')
    expect(noMx.find(f => f.title.startsWith('Sem registro DMARC'))?.severity).toBe('low')
  })

  it('flagra SPF permissivo +all como high', async () => {
    const fs = await new DnsAgent(mock({ 'exemplo.com': [['v=spf1 +all']], '_dmarc.exemplo.com': [['v=DMARC1; p=reject']] })).run(scopeFor('https://exemplo.com'))
    const spf = fs.find(f => f.title.startsWith('SPF permissivo'))
    expect(spf?.severity).toBe('high')
  })

  it('flagra DMARC p=none como low e não flagra SPF quando -all', async () => {
    const fs = await new DnsAgent(mock({ 'exemplo.com': [['v=spf1 -all']], '_dmarc.exemplo.com': [['v=DMARC1; p=none']] })).run(scopeFor('https://exemplo.com'))
    expect(fs.find(f => f.title.startsWith('DMARC em modo monitor'))?.severity).toBe('low')
    expect(fs.find(f => f.title.includes('SPF'))).toBeUndefined()
  })

  it('pula IP e host de 1 label (não têm SPF/DMARC)', async () => {
    const agent = new DnsAgent(mock({}))
    expect(await agent.run(scopeFor('http://127.0.0.1:3000'))).toHaveLength(0)
    expect(await agent.run(scopeFor('http://localhost:3000'))).toHaveLength(0)
  })

  it('domínio bem configurado (SPF -all + DMARC reject, sem MX) → sem achados', async () => {
    const fs = await new DnsAgent(mock({ 'exemplo.com': [['v=spf1 include:x -all']], '_dmarc.exemplo.com': [['v=DMARC1; p=reject']] })).run(scopeFor('https://exemplo.com'))
    expect(fs).toHaveLength(0)
  })

  it('DKIM não encontrado + tem MX → info', async () => {
    const r = await analyzeEmailDns('exemplo.com', mock(
      { 'exemplo.com': [['v=spf1 -all']], '_dmarc.exemplo.com': [['v=DMARC1; p=reject']] },
      { 'exemplo.com': [{ exchange: 'mx.exemplo.com', priority: 10 }] },
    ))
    expect(r.hasMx).toBe(true)
    expect(r.dkim.found).toHaveLength(0)
  })
})
