import { describe, it, expect } from 'vitest'
import { interpretGitleaks } from '../index.js'

/**
 * Testes da decisão pura sobre o resultado do gitleaks. O bug crítico (#8):
 * no Windows, `runCommand` com `shell:true` faz um binário ausente RESOLVER com
 * code=1 + stderr "não é reconhecido" + relatório ausente — e o código antigo
 * tratava "code 1 + sem relatório" como "limpo" (`return []`), produzindo um
 * veredito ✅ PASSOU silencioso num repo cheio de segredos.
 */
describe('interpretGitleaks', () => {
  const LEAKS = JSON.stringify([{ RuleID: 'aws-key', File: 'a.ts', StartLine: 1 }])

  it('SKIP quando o binário não foi reconhecido (shell:true Windows, pt-BR)', () => {
    const out = interpretGitleaks({
      code: 1,
      stderr: "'gitleaks' não é reconhecido como um comando interno\nou externo",
      report: null,
    })
    expect(out.kind).toBe('skip')
  })

  it('SKIP quando o binário não foi reconhecido (en, "not recognized")', () => {
    const out = interpretGitleaks({
      code: 1,
      stderr: "'gitleaks' is not recognized as an internal or external command",
      report: null,
    })
    expect(out.kind).toBe('skip')
  })

  it('SKIP em "command not found" (shell POSIX, code 127)', () => {
    const out = interpretGitleaks({ code: 127, stderr: 'gitleaks: command not found', report: null })
    expect(out.kind).toBe('skip')
  })

  it('SKIP mesmo com mojibake do codepage do Windows (cmd.exe CP850/1252)', () => {
    // No cmd.exe pt-BR a stderr chega mutilada: "não é" -> "n�o �". O token
    // "reconhecido" (sem acento) sobrevive e deve bastar para detectar a ausência.
    const out = interpretGitleaks({
      code: 1,
      stderr: "'gitleaks' n�o � reconhecido como um comando interno\nou externo",
      report: null,
    })
    expect(out.kind).toBe('skip')
  })

  it('limpo: code 0 sem relatório → findings vazio', () => {
    const out = interpretGitleaks({ code: 0, stderr: '', report: null })
    expect(out).toEqual({ kind: 'findings', findings: [] })
  })

  it('limpo: code 0 com relatório vazio → findings vazio', () => {
    const out = interpretGitleaks({ code: 0, stderr: '', report: '   ' })
    expect(out).toEqual({ kind: 'findings', findings: [] })
  })

  it('vazamentos: code 1 com relatório JSON → findings parseados', () => {
    const out = interpretGitleaks({ code: 1, stderr: '', report: LEAKS })
    expect(out.kind).toBe('findings')
    if (out.kind === 'findings') {
      expect(out.findings).toHaveLength(1)
      expect(out.findings[0].RuleID).toBe('aws-key')
    }
  })

  it('NUNCA limpo silencioso: code 1 SEM relatório e sem assinatura de ausência → ERROR', () => {
    const out = interpretGitleaks({ code: 1, stderr: 'algum erro inesperado', report: null })
    expect(out.kind).toBe('error')
  })

  it('código inesperado (ex.: 2) → ERROR, nunca "limpo"', () => {
    const out = interpretGitleaks({ code: 2, stderr: 'panic', report: null })
    expect(out.kind).toBe('error')
  })
})
