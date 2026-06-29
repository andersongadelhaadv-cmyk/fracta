import { describe, it, expect } from 'vitest'
import { InMemoryRateLimiter } from '../rate-limiter.js'

describe('InMemoryRateLimiter', () => {
  it('allows up to the limit, then blocks within the window', () => {
    let now = 1000
    const rl = new InMemoryRateLimiter({ limit: 3, windowMs: 1000, now: () => now })
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(false)
  })
  it('resets after the window passes', () => {
    let now = 1000
    const rl = new InMemoryRateLimiter({ limit: 1, windowMs: 1000, now: () => now })
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(false)
    now = 2100
    expect(rl.check('ip1').allowed).toBe(true)
  })
  it('isolates different IPs', () => {
    let now = 1000
    const rl = new InMemoryRateLimiter({ limit: 1, windowMs: 1000, now: () => now })
    expect(rl.check('a').allowed).toBe(true)
    expect(rl.check('b').allowed).toBe(true)
  })
})
