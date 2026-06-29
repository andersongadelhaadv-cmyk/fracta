import { describe, it, expect } from 'vitest'
import { findCookieIssues } from '../cookie-check.js'

describe('findCookieIssues', () => {
  it('flags a cookie missing Secure/HttpOnly/SameSite', () => {
    const f = findCookieIssues(['sid=abc'], 'demo', 'run1')
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('low')
    expect(f[0].title).toContain('sid')
  })
  it('passes a fully-flagged cookie', () => {
    expect(findCookieIssues(['sid=abc; Secure; HttpOnly; SameSite=Lax'], 'demo', 'run1')).toHaveLength(0)
  })
  it('returns [] when there are no cookies', () => {
    expect(findCookieIssues([], 'demo', 'run1')).toEqual([])
  })
})
