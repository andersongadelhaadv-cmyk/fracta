import { describe, it, expect } from 'vitest'
import { SqliteScanStore } from '../scan-store.js'
import type { PassiveScanResult } from '../types.js'

const result = (url: string): PassiveScanResult => ({
  url, findings: [], grade: 'A', score: 100, verdict: 'ok',
  checks: [{ name: 'security-headers', status: 'ok' }],
  scannedAt: '2026-06-29T00:00:00.000Z',
})

describe('SqliteScanStore', () => {
  it('saves with an injected id and reads it back by shareId', () => {
    const s = new SqliteScanStore(':memory:')
    const id = s.save(result('https://a.example'), { genId: () => 'fixed-id' })
    expect(id).toBe('fixed-id')
    expect(s.getByShareId('fixed-id')?.url).toBe('https://a.example')
    expect(s.getByShareId('nope')).toBeNull()
  })
  it('returns a cached result within the TTL and null after', () => {
    const s = new SqliteScanStore(':memory:')
    let now = 10_000
    s.save(result('https://b.example'), { genId: () => 'b1', now: () => now })
    expect(s.getCached('https://b.example', 5_000, now)?.url).toBe('https://b.example')
    expect(s.getCached('https://b.example', 5_000, now + 6_000)).toBeNull()
  })
  it('stores captured emails', () => {
    const s = new SqliteScanStore(':memory:')
    s.saveEmail('a@b.com', 'waitlist')
    expect(s.countEmails()).toBe(1)
  })
  it('getCachedEntry returns the existing shareId within TTL (no re-mint)', () => {
    const s = new SqliteScanStore(':memory:')
    let now = 10_000
    const id = s.save(result('https://c.example'), { genId: () => 'c1', now: () => now })
    const hit = s.getCachedEntry('https://c.example', 5_000, now)
    expect(hit?.shareId).toBe(id)
    expect(hit?.result.url).toBe('https://c.example')
    expect(s.getCachedEntry('https://c.example', 5_000, now + 6_000)).toBeNull()
  })
  it('pruneOlderThan removes stale scans', () => {
    const s = new SqliteScanStore(':memory:')
    s.save(result('https://old.example'), { genId: () => 'old', now: () => 1_000 })
    s.save(result('https://new.example'), { genId: () => 'new', now: () => 1_000_000 })
    const removed = s.pruneOlderThan(100_000, 1_000_000) // corta o que for mais velho que 900_000
    expect(removed).toBe(1)
    expect(s.getByShareId('old')).toBeNull()
    expect(s.getByShareId('new')?.url).toBe('https://new.example')
  })
})
