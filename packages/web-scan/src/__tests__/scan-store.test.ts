import { describe, it, expect } from 'vitest'
import { SqliteScanStore } from '../scan-store.js'
import type { PassiveScanResult } from '../types.js'

const result = (url: string): PassiveScanResult => ({
  url, findings: [], grade: 'A', score: 100, verdict: 'ok', scannedAt: '2026-06-29T00:00:00.000Z',
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
})
