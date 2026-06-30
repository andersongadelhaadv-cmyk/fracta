import { describe, it, expect } from 'vitest'
import { checkLgpdLite, findPrivacyHref } from '../lgpd-lite.js'

const find = (fs: ReturnType<typeof checkLgpdLite>, rulePart: string) =>
  fs.find((f) => f.title.toLowerCase().includes(rulePart))

describe('checkLgpdLite (v2)', () => {
  // 1) política de privacidade
  it('flags missing privacy-policy link (low)', () => {
    const f = checkLgpdLite('<html><body>oi</body></html>', [], 'demo', 'run1')
    const pp = find(f, 'política de privacidade')
    expect(pp).toBeDefined()
    expect(pp?.severity).toBe('low')
  })
  it('does not flag privacy link when present', () => {
    const html = '<a href="/politica-de-privacidade">Privacidade</a>'
    expect(find(checkLgpdLite(html, [], 'demo', 'run1'), 'política de privacidade')).toBeUndefined()
  })

  // 2) rastreadores de terceiros → info (não penaliza)
  it('detects third-party trackers as INFO (0 pts), listing them', () => {
    const html = '<script src="https://www.googletagmanager.com/gtag/js"></script> privacidade'
    const f = checkLgpdLite(html, [], 'demo', 'run1')
    const tr = find(f, 'rastreadores de terceiros')
    expect(tr).toBeDefined()
    expect(tr?.severity).toBe('info')
    expect(tr?.description).toContain('Google Analytics')
  })
  it('notes absence of consent banner when trackers present without consent signal', () => {
    const html = '<script src="https://connect.facebook.net/x/fbevents.js"></script> privacidade'
    const tr = find(checkLgpdLite(html, [], 'demo', 'run1'), 'rastreadores de terceiros')
    expect(tr?.description).toMatch(/NÃO vi sinais de banner de consentimento/)
  })
  it('acknowledges a consent banner when present', () => {
    const html = '<script src="https://www.google-analytics.com/ga.js"></script> aceitar cookies privacidade'
    const tr = find(checkLgpdLite(html, [], 'demo', 'run1'), 'rastreadores de terceiros')
    expect(tr?.description).toMatch(/banner de consentimento/i)
    expect(tr?.description).not.toMatch(/NÃO vi sinais/)
  })
  it('does not flag trackers when none present', () => {
    expect(find(checkLgpdLite('<html>privacidade</html>', [], 'demo', 'run1'), 'rastreadores')).toBeUndefined()
  })

  // 3) cookie de rastreamento no primeiro acesso → low
  it('flags a tracking cookie set on first load (low)', () => {
    const f = checkLgpdLite('<html>privacidade</html>', ['_ga=GA1.1.123; Path=/'], 'demo', 'run1')
    const ck = find(f, 'cookie de rastreamento')
    expect(ck).toBeDefined()
    expect(ck?.severity).toBe('low')
    expect(ck?.evidence).toContain('_ga')
  })
  it('does not flag a non-tracking (session) cookie', () => {
    const f = checkLgpdLite('<html>privacidade</html>', ['sid=abc; HttpOnly'], 'demo', 'run1')
    expect(find(f, 'cookie de rastreamento')).toBeUndefined()
  })

  it('a clean page (privacy link, no trackers, no tracking cookies) yields no findings', () => {
    expect(checkLgpdLite('<a href="/privacidade">Privacidade</a>', ['sid=x; Secure'], 'demo', 'run1')).toEqual([])
  })

  // 4) leitura determinística da política de privacidade
  const PADDING = ' lorem ipsum '.repeat(30)
  it('reads the policy and reports it covers all key disclosures', () => {
    const text =
      'Política de Privacidade. O encarregado (DPO) atende em dpo@x.com. A base legal é o consentimento e a ' +
      'execução de contrato. Você tem os direitos do titular do Art. 18 (portabilidade, eliminação). Retenção: ' +
      'guardamos os dados pelo prazo necessário. Há transferência internacional com cláusulas-padrão.' + PADDING
    const f = checkLgpdLite('<a href="/privacidade">x</a>', [], 'demo', 'run1', { text, url: 'https://x/privacidade' })
    const a = find(f, 'política de privacidade analisada')
    expect(a).toBeDefined()
    expect(a?.severity).toBe('info')
    expect(a?.description).toMatch(/menciona todos os itens-chave/i)
  })
  it('reads the policy and lists missing disclosures', () => {
    const text = 'Política de Privacidade. Coletamos seu nome e e-mail para melhorar a experiência do site.' + PADDING
    const a = find(checkLgpdLite('<a href="/p">x</a>', [], 'demo', 'run1', { text, url: 'https://x/p' }), 'política de privacidade analisada')
    expect(a).toBeDefined()
    expect(a?.description).toMatch(/NÃO encontrei menção clara a/i)
    expect(a?.description).toMatch(/transferência internacional/i)
  })
  it('does not run policy analysis when no policy was read', () => {
    const f = checkLgpdLite('<a href="/privacidade">x</a>', [], 'demo', 'run1')
    expect(find(f, 'política de privacidade analisada')).toBeUndefined()
  })

  describe('findPrivacyHref', () => {
    it('finds the privacy policy href by url', () => {
      expect(findPrivacyHref('<a href="/politica-de-privacidade">Termos</a>')).toBe('/politica-de-privacidade')
    })
    it('finds it by anchor text', () => {
      expect(findPrivacyHref('<a href="/legal/x">Política de Privacidade</a>')).toBe('/legal/x')
    })
    it('returns null when absent', () => {
      expect(findPrivacyHref('<a href="/sobre">Sobre</a>')).toBeNull()
    })
  })
})
