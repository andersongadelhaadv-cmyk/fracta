import { describe, it, expect } from 'vitest'
import { interpretSemgrep, mapSemgrepFindings, semgrepSkipReasonFor, type SemgrepRawResult } from '../index.js'

function raw(over: Partial<SemgrepRawResult> & { extra?: Partial<SemgrepRawResult['extra']> } = {}): SemgrepRawResult {
  return {
    check_id: 'javascript.express.security.audit.xss.direct-response-write',
    path: 'src/app.ts',
    start: { line: 42 },
    ...over,
    extra: {
      message: 'Detected directly writing user input to the response',
      severity: 'ERROR',
      metadata: { cwe: ['CWE-79: Cross-site Scripting'], owasp: ['A03:2021 - Injection'], confidence: 'HIGH' },
      lines: 'res.send(req.query.q)',
      ...(over.extra ?? {}),
    },
  }
}

describe('interpretSemgrep', () => {
  it('SKIP quando o binário não é reconhecido (Windows/POSIX)', () => {
    expect(interpretSemgrep({ code: 127, stdout: '', stderr: 'semgrep: command not found' }).kind).toBe('skip')
    expect(interpretSemgrep({ code: 1, stdout: '', stderr: "'semgrep' não é reconhecido como um comando interno" }).kind).toBe('skip')
  })

  it('JSON com results → findings parseados', () => {
    const out = interpretSemgrep({ code: 1, stdout: JSON.stringify({ results: [raw()], errors: [] }), stderr: '' })
    expect(out.kind).toBe('findings')
    if (out.kind === 'findings') {
      expect(out.results).toHaveLength(1)
      expect(out.results[0].check_id).toContain('xss')
    }
  })

  it('JSON com results vazio e code 0 → findings vazio (limpo)', () => {
    const out = interpretSemgrep({ code: 0, stdout: JSON.stringify({ results: [], errors: [] }), stderr: '' })
    expect(out.kind).toBe('findings')
    if (out.kind === 'findings') expect(out.results).toHaveLength(0)
  })

  it('NUNCA falso-limpo: sem JSON parseável e code de erro → error', () => {
    expect(interpretSemgrep({ code: 2, stdout: 'panic', stderr: 'fatal' }).kind).toBe('error')
  })
})

describe('semgrepSkipReasonFor', () => {
  it('ENOENT (binário ausente) → motivo de skip', () => {
    expect(semgrepSkipReasonFor(Object.assign(new Error('spawn semgrep'), { code: 'ENOENT' }))).toMatch(/não encontrado/i)
  })
  it('timeout (semgrep lento no Windows) → motivo de skip', () => {
    expect(semgrepSkipReasonFor(new Error('timeout após 120000ms ao executar: semgrep'))).toMatch(/excedeu o tempo/i)
  })
  it('erro real de execução → null (re-lança, nunca falso-verde)', () => {
    expect(semgrepSkipReasonFor(new Error('permission denied'))).toBeNull()
  })
})

describe('mapSemgrepFindings', () => {
  const base = { saas: 'demo', runId: 'run-1' }

  it('mapeia severidade, location file:line e CWE nas references', () => {
    const f = mapSemgrepFindings({ ...base, results: [raw()] })
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('high') // ERROR
    expect(f[0].location).toEqual({ file: 'src/app.ts', line: 42 })
    expect(f[0].references?.some(r => /CWE-79/.test(r))).toBe(true)
    expect(f[0].agent).toBe('SEMGREP Agent')
    expect(f[0].category).toBe('code')
    expect(f[0].id).toBeTruthy()
  })

  it('ERROR/WARNING/INFO → high/medium/low', () => {
    const f = mapSemgrepFindings({ ...base, results: [
      raw({ check_id: 'a', extra: { severity: 'ERROR' } }),
      raw({ check_id: 'b', extra: { severity: 'WARNING' } }),
      raw({ check_id: 'c', extra: { severity: 'INFO' } }),
    ] })
    expect(f.map(x => x.severity)).toEqual(['high', 'medium', 'low'])
  })

  it('confidence vem do metadata (HIGH→high); default medium quando ausente', () => {
    const f = mapSemgrepFindings({ ...base, results: [
      raw({ check_id: 'hi', extra: { metadata: { confidence: 'HIGH' } } }),
      raw({ check_id: 'none', extra: { metadata: {} } }),
    ] })
    expect(f[0].confidence).toBe('high')
    expect(f[1].confidence).toBe('medium')
  })

  it('results vazio → []', () => {
    expect(mapSemgrepFindings({ ...base, results: [] })).toEqual([])
  })
})
