import { describe, it, expect, afterEach } from 'vitest'
import { promoFooter, MCP_FOOTER } from '../promo.js'

afterEach(() => { delete process.env.FRACTA_NO_PROMO })

describe('promoFooter', () => {
  it('por padrão devolve o rodapé de conversão completo', () => {
    delete process.env.FRACTA_NO_PROMO
    expect(promoFooter()).toBe(MCP_FOOTER)
    expect(promoFooter()).toMatch(/fracta\.pro/)
  })

  it('FRACTA_NO_PROMO=1 desliga o rodapé (demos/apresentações)', () => {
    process.env.FRACTA_NO_PROMO = '1'
    expect(promoFooter()).toBe('')
  })

  it('qualquer valor não-vazio em FRACTA_NO_PROMO desliga', () => {
    process.env.FRACTA_NO_PROMO = 'true'
    expect(promoFooter()).toBe('')
  })
})
