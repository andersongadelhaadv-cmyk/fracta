import { describe, it, expect } from 'vitest'
import type { Finding } from '@fracta/core'
import { fmtFinding, sastConfidenceSummary } from '../sast-format.js'

// Só os campos que o formatador usa (o Finding real tem muito mais).
const f = (severity: Finding['severity'], confidence: Finding['confidence'], title = 't'): Pick<Finding, 'severity' | 'title' | 'confidence'> =>
  ({ severity, title, confidence })

describe('fmtFinding', () => {
  it('marca achado de baixa confiança (self-detection/fixture)', () => {
    expect(fmtFinding(f('high', 'low', 'SQLi'))).toBe('- [high · baixa confiança] SQLi')
  })
  it('não marca achado de alta confiança', () => {
    expect(fmtFinding(f('high', 'high', 'SQLi'))).toBe('- [high] SQLi')
    expect(fmtFinding(f('medium', undefined, 'X'))).toBe('- [medium] X')
  })
})

describe('sastConfidenceSummary', () => {
  it('conta CONFIRMADOS (alta confiança) separado dos de baixa confiança', () => {
    // 6 high self-detection (low) + 1 high real + 1 medium real
    const findings = [
      ...Array.from({ length: 6 }, () => f('high', 'low')),
      f('high', 'high'),
      f('medium', 'high'),
    ]
    const s = sastConfidenceSummary(findings)
    expect(s).toContain('1 high')     // só o high confirmado conta
    expect(s).toContain('1 medium')
    expect(s).toMatch(/\+6 de baixa confiança/) // os 6 self-detection sinalizados
    expect(s).not.toMatch(/7 high/)   // NÃO alarma com o total bruto
  })
  it('sem achados de baixa confiança, não menciona a ressalva', () => {
    const s = sastConfidenceSummary([f('high', 'high'), f('critical', 'high')])
    expect(s).toContain('1 critical')
    expect(s).toContain('1 high')
    expect(s).not.toMatch(/baixa confiança/)
  })
})
