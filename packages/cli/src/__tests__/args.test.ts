import { describe, it, expect } from 'vitest'
import { parseCliArgs, CliUsageError } from '../args.js'

describe('parseCliArgs', () => {
  it('flag desconhecida → CliUsageError com mensagem HONESTA (não o TypeError cru do Node)', () => {
    let err: unknown
    try {
      parseCliArgs(['--flagInexistente'])
    } catch (e) {
      err = e
    }
    expect(err).toBeInstanceOf(CliUsageError)
    const msg = (err as Error).message
    expect(msg).toMatch(/Opção desconhecida/)
    expect(msg).toContain('--flagInexistente')
    // NUNCA vaza o código de erro interno do Node nem o `}` solto do dump do objeto.
    expect(msg).not.toMatch(/ERR_PARSE_ARGS/)
    expect(msg).not.toMatch(/TypeError/)
  })

  it('--version é SUPORTADO (convenção universal de CLI) — não lança', () => {
    const { values } = parseCliArgs(['--version'])
    expect(values.version).toBe(true)
  })

  it('-V (short) também imprime versão', () => {
    const { values } = parseCliArgs(['-V'])
    expect(values.version).toBe(true)
  })

  it('parsing normal segue intacto (scan --target x --depth full)', () => {
    const { values, positionals } = parseCliArgs(['scan', '--target', 'meu-saas', '--depth', 'full'])
    expect(positionals[0]).toBe('scan')
    expect(values.target).toBe('meu-saas')
    expect(values.depth).toBe('full')
  })
})
