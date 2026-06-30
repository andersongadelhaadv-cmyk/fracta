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
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) {
      expect(isBlockedIp(ip), ip).toBe(false)
    }
  })
  it('does NOT treat 172.32.x / 11.x as private (boundary)', () => {
    expect(isBlockedIp('172.32.0.1')).toBe(false)
    expect(isBlockedIp('11.0.0.1')).toBe(false)
  })
  it('blocks IPv6 loopback/link-local/ula/multicast', () => {
    for (const ip of ['::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::', 'ff02::1', 'fd00:ec2::254']) {
      expect(isBlockedIp(ip), ip).toBe(true)
    }
  })
  it('allows public IPv6', () => {
    expect(isBlockedIp('2606:4700:4700::1111')).toBe(false)
  })
  // C3: formas IPv6 que embutem um IPv4 interno (bypass clássico do guard).
  it('blocks IPv4-mapped/NAT64/6to4 IPv6 that embed an internal v4', () => {
    for (const ip of [
      '::ffff:7f00:1',          // ::ffff:127.0.0.1 (hex) — loopback
      '::ffff:127.0.0.1',       // mapeado dotted — loopback
      '::ffff:a9fe:a9fe',       // ::ffff:169.254.169.254 — metadata AWS
      '0:0:0:0:0:ffff:7f00:1',  // mapeado expandido — loopback
      '64:ff9b::7f00:1',        // NAT64 → 127.0.0.1
      '2002:7f00:0001::',       // 6to4 → 127.0.0.1
    ]) {
      expect(isBlockedIp(ip), ip).toBe(true)
    }
  })
  it('allows IPv4-mapped IPv6 of a PUBLIC address', () => {
    expect(isBlockedIp('::ffff:8.8.8.8')).toBe(false)
    expect(isBlockedIp('::ffff:0808:0808')).toBe(false)
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
  it('rejects embedded credentials (userinfo)', async () => {
    await expect(validateScanUrl('http://user:pass@good.example', { resolve })).rejects.toThrow(SsrfError)
  })
  it('rejects internal-service ports even on a public host', async () => {
    await expect(validateScanUrl('http://good.example:6379', { resolve })).rejects.toThrow(SsrfError)
    await expect(validateScanUrl('http://good.example:22', { resolve })).rejects.toThrow(SsrfError)
  })
  it('blocks a literal IPv4-mapped IPv6 host that embeds loopback', async () => {
    await expect(validateScanUrl('http://[::ffff:7f00:1]/', { resolve })).rejects.toThrow(SsrfError)
  })
})
