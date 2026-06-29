import { describe, it, expect } from 'vitest'
import { makeValidatingLookup } from '../safe-fetch.js'

/**
 * O lookup validador é o que fecha SSRF por redirect/rebinding: ele roda no
 * momento da conexão e recusa qualquer IP bloqueado. Testamos o contrato direto
 * (sem rede real) — note que ele delega ao dns.lookup do SO para hostnames.
 */
describe('makeValidatingLookup', () => {
  it('rejeita conexão a um IP literal interno (loopback)', async () => {
    const lookup = makeValidatingLookup(false)
    const err = await new Promise<Error | null>((resolve) => {
      lookup('127.0.0.1', { family: 4 }, (e) => resolve(e))
    })
    expect(err).toBeInstanceOf(Error)
    expect((err as NodeJS.ErrnoException).code).toBe('ESSRFBLOCKED')
  })

  it('rejeita IPv4-mapped IPv6 que embute metadata (169.254.169.254)', async () => {
    const lookup = makeValidatingLookup(false)
    const err = await new Promise<Error | null>((resolve) => {
      lookup('::ffff:a9fe:a9fe', { family: 6 }, (e) => resolve(e))
    })
    expect(err).toBeInstanceOf(Error)
  })

  it('permite IP público', async () => {
    const lookup = makeValidatingLookup(false)
    const { err, address } = await new Promise<{ err: Error | null; address: unknown }>((resolve) => {
      lookup('8.8.8.8', { family: 4 }, (e, a) => resolve({ err: e, address: a }))
    })
    expect(err).toBeNull()
    expect(address).toBe('8.8.8.8')
  })

  it('com allowPrivate=true (teste), permite loopback', async () => {
    const lookup = makeValidatingLookup(true)
    const { err } = await new Promise<{ err: Error | null }>((resolve) => {
      lookup('127.0.0.1', { family: 4 }, (e) => resolve({ err: e }))
    })
    expect(err).toBeNull()
  })
})
