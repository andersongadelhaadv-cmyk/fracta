import { describe, it, expect } from 'vitest'
import { grade } from '../grader.js'
import type { Finding } from '@fracta/core'

const f = (severity: Finding['severity']): Finding => ({
  id: severity, runId: 'r', agent: 'a', category: 'security', camada: 'security',
  severity, title: 't', description: 'd', recommendation: 'r', createdAt: new Date(),
})

describe('grade', () => {
  it('A + 100 when there are no findings', () => {
    expect(grade([])).toEqual({ grade: 'A', score: 100 })
  })
  it('subtracts by severity and never goes below 0', () => {
    const r = grade([f('critical'), f('critical'), f('critical'), f('critical')])
    expect(r.score).toBe(0)
    expect(r.grade).toBe('F')
  })
  it('a single low stays high', () => {
    const r = grade([f('low')])
    expect(r.score).toBe(97)
    expect(r.grade).toBe('A')
  })
})
