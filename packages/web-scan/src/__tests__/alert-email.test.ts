import { describe, it, expect } from 'vitest'
import { formatAlertEmail } from '../alert-email.js'
import type { ScanDiff } from '../diff.js'
import type { Finding } from '@fracta/core'

const finding = (title: string, severity: Finding['severity'] = 'high'): Finding =>
  ({ id: title, runId: 'r', agent: 'HEADERS', category: 'headers', severity, title, description: '', recommendation: '', createdAt: new Date() }) as unknown as Finding

const base: ScanDiff = {
  url: 'https://meusaas.com.br/', previousGrade: 'A', currentGrade: 'D',
  gradeDelta: 'worsened', newFindings: [finding('HSTS ausente')], resolvedFindings: [], changed: true, regressed: true,
}
const opts = { reportUrl: 'https://fracta.pro/r/abc', unsubUrl: 'https://fracta.pro/api/unsubscribe?token=t' }

describe('formatAlertEmail', () => {
  it('nota caiu → assunto mostra a queda + host', () => {
    const e = formatAlertEmail(base, opts)
    expect(e.subject).toContain('meusaas.com.br')
    expect(e.subject).toMatch(/A.*D|piorou/)
  })

  it('corpo lista os achados NOVOS + link do relatório + opt-out', () => {
    const e = formatAlertEmail(base, opts)
    expect(e.text).toContain('HSTS ausente')
    expect(e.text).toContain(opts.reportUrl)
    expect(e.text).toContain(opts.unsubUrl)
    expect(e.html).toContain(opts.unsubUrl) // opt-out 1-clique também no HTML
  })

  it('mesma nota + achado novo → assunto de "novo problema" (não fala em queda)', () => {
    const d: ScanDiff = { ...base, previousGrade: 'B', currentGrade: 'B', gradeDelta: 'same', newFindings: [finding('CSP fraca')] }
    const e = formatAlertEmail(d, opts)
    expect(e.subject).not.toMatch(/→/)
    expect(e.subject.toLowerCase()).toMatch(/novo|problema|achado/)
    expect(e.text).toContain('CSP fraca')
  })
})
