import { describe, it, expect } from 'vitest'
import { analyzeCsp } from '../csp.js'

const rules = (policy: string) => analyzeCsp(policy).map(i => i.rule)
const sevOf = (policy: string, rule: string) => analyzeCsp(policy).find(i => i.rule === rule)?.severity

describe('analyzeCsp', () => {
  it("'unsafe-inline' em script-src → high", () => {
    expect(sevOf("default-src 'self'; script-src 'self' 'unsafe-inline'", 'csp-unsafe-inline-script')).toBe('high')
  })
  it("nonce em script-src neutraliza o unsafe-inline (não flagra)", () => {
    expect(rules("script-src 'self' 'unsafe-inline' 'nonce-abc'")).not.toContain('csp-unsafe-inline-script')
  })
  it("'unsafe-eval' → medium", () => {
    expect(sevOf("default-src 'self'; script-src 'self' 'unsafe-eval'", 'csp-unsafe-eval')).toBe('medium')
  })
  it('script-src amplo (*) → medium', () => {
    expect(sevOf("script-src *", 'csp-broad-script-src')).toBe('medium')
  })
  it('sem script-src nem default-src → medium', () => {
    expect(rules("img-src 'self'")).toContain('csp-no-script-src')
  })
  it("object-src 'none' presente → sem issue de object-src", () => {
    expect(rules("default-src 'self'; object-src 'none'; base-uri 'self'")).not.toContain('csp-object-src')
  })
  it('policy estrita → só endurecimentos low (sem high/medium)', () => {
    const issues = analyzeCsp("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    expect(issues.every(i => i.severity === 'low' || i.severity === 'info')).toBe(true)
    expect(issues.some(i => i.severity === 'high' || i.severity === 'medium')).toBe(false)
  })
})
