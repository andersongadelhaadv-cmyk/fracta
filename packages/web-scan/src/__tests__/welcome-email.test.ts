import { describe, it, expect } from 'vitest'
import { formatWelcomeEmail } from '../welcome-email.js'

const opts = {
  url: 'https://meusaas.com.br/',
  unsubUrl: 'https://fracta.pro/api/unsubscribe?token=t',
  headerSrc: 'https://fracta.pro/email/monitor-welcome.png',
}

describe('formatWelcomeEmail', () => {
  it('assunto confirma o alvo monitorado (host)', () => {
    expect(formatWelcomeEmail(opts).subject).toContain('meusaas.com.br')
  })

  it('texto explica o gatilho (regressão) + opt-out', () => {
    const e = formatWelcomeEmail(opts)
    expect(e.text.toLowerCase()).toMatch(/piorar|regress/)
    expect(e.text).toContain(opts.unsubUrl)
  })

  it('html embute o header (img headerSrc) + opt-out, e reusa o headerSrc dado (cid ou https)', () => {
    const e = formatWelcomeEmail(opts)
    expect(e.html).toContain(`src="${opts.headerSrc}"`)
    expect(e.html).toContain(opts.unsubUrl)
    // funciona com cid inline também
    const cid = formatWelcomeEmail({ ...opts, headerSrc: 'cid:fractaheader' })
    expect(cid.html).toContain('src="cid:fractaheader"')
  })
})
