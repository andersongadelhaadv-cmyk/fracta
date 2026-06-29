import { describe, it, expect } from 'vitest'
import { isBlockedIp, validateScanUrl } from '../ssrf-guard.js'
import { SsrfError } from '../types.js'

describe('isBlockedIp', () => {
  it('blocks IPv4 loopback/private/link-local/metadata/unspecified', () => {
    for (const ip of ['127.0.0.1', '127.5.5.5', '10.0.0.1', '172.16.0.1', '172.31.255.255',
      '192.168.1.1', '169.254.169.254', '0.0.0.0']) {
      expect(isBlockedIp(ip), ip).toBe(true)
    }
  })
  it('allows normal public IPv4', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '76.13.170.79']) {
      expect(isBlockedIp(ip), ip).toBe(false)
    }
  })
  it('does NOT treat 172.32.x / 11.x as private (boundary)', () => {
    expect(isBlockedIp('172.32.0.1')).toBe(false)
    expect(isBlockedIp('11.0.0.1')).toBe(false)
  })
  it('blocks IPv6 loopback/link-local/ula', () => {
    for (const ip of ['::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::']) {
      expect(isBlockedIp(ip), ip).toBe(true)
    }
  })
  it('allows public IPv6', () => {
    expect(isBlockedIp('2606:4700:4700::1111')).toBe(false)
  })
})

describe('validateScanUrl', () => {
  // resolver fake: mapeia host -> IPs (sem DNS real)
  const resolve = (host: string) => Promise.resolve(
    host === 'evil.internal' ? ['10.0.0.5'] :
    host === 'good.example' ? ['93.184.216.34'] : []
  )
  it('rejects non-http(s) schemes', async () => {
    await expect(validateScanUrl('ftp://good.example', { resolve })).rejects.toThrow(SsrfError)
    await expect(validateScanUrl('file:///etc/passwd', { resolve })).rejects.toThrow(SsrfError)
  })
  it('rejects a host that resolves to a private IP', async () => {
    await expect(validateScanUrl('http://evil.internal', { resolve })).rejects.toThrow(SsrfError)
  })
  it('rejects a literal private IP host', async () => {
    await expect(validateScanUrl('http://169.254.169.254/latest/meta-data', { resolve })).rejects.toThrow(SsrfError)
  })
  it('rejects a host with no resolvable address', async () => {
    await expect(validateScanUrl('http://nxdomain.test', { resolve })).rejects.toThrow(SsrfError)
  })
  it('accepts a public https URL and returns a normalized URL', async () => {
    const u = await validateScanUrl('good.example/path', { resolve })
    expect(u.protocol).toBe('https:')
    expect(u.hostname).toBe('good.example')
  })
})
