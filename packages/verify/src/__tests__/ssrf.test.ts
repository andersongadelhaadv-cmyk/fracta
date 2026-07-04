import { describe, it, expect } from 'vitest'
import { isPrivateIp, assertPublicHost } from '../ssrf.js'
import { SsrfError } from '../errors.js'

describe('isPrivateIp', () => {
  it('reconhece faixas privadas e loopback', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true)
    expect(isPrivateIp('10.1.2.3')).toBe(true)
    expect(isPrivateIp('192.168.0.5')).toBe(true)
    expect(isPrivateIp('169.254.1.1')).toBe(true)
    expect(isPrivateIp('::1')).toBe(true)
    expect(isPrivateIp('8.8.8.8')).toBe(false)
  })

  it('fecha bypasses: IPv4-mapeado-em-IPv6, CGNAT e caixa alta', () => {
    expect(isPrivateIp('::ffff:127.0.0.1')).toBe(true)   // IPv4-mapped IPv6
    expect(isPrivateIp('::ffff:192.168.1.1')).toBe(true)
    expect(isPrivateIp('FE80::1')).toBe(true)            // uppercase IPv6 link-local
    expect(isPrivateIp('100.64.0.1')).toBe(true)         // CGNAT 100.64/10
    expect(isPrivateIp('100.128.0.1')).toBe(false)       // fora do CGNAT → público
  })
})

describe('assertPublicHost', () => {
  it('recusa host que resolve para IP privado', async () => {
    const resolver = async () => ['192.168.1.10']
    await expect(assertPublicHost('intranet.local', { resolver })).rejects.toBeInstanceOf(SsrfError)
  })

  it('aceita host público', async () => {
    const resolver = async () => ['93.184.216.34']
    await expect(assertPublicHost('example.com', { resolver })).resolves.toBeUndefined()
  })

  it('permite privado só com allowPrivate (teste/local)', async () => {
    const resolver = async () => ['127.0.0.1']
    await expect(assertPublicHost('localhost', { resolver, allowPrivate: true })).resolves.toBeUndefined()
  })
})
