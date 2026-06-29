import { lookup as dnsLookup } from 'node:dns'
import { Agent } from 'undici'
import { FractaHttpClient } from '@fracta/core'
import { isBlockedIp } from './ssrf-guard.js'

type LookupCb = (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => void

/**
 * Lookup que valida o IP REAL no momento da conexão. Delega ao `dns.lookup`
 * (preservando o contrato esperado pelo undici) e converte em erro qualquer
 * endereço bloqueado. Como o undici chama este lookup a CADA conexão — inclusive
 * em cada hop de redirect que o `fetch` seguir — isto fecha SSRF por redirect
 * (C1) e por DNS rebinding/TOCTOU (C2) de uma vez: o IP validado é exatamente o
 * IP usado para conectar.
 */
export function makeValidatingLookup(allowPrivate: boolean) {
  return (hostname: string, options: unknown, callback: LookupCb): void => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    dnsLookup(hostname, options as any, (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => {
      if (err) return callback(err, address, family)
      const list = Array.isArray(address)
        ? (address as Array<{ address: string }>).map((a) => a.address)
        : [address as string]
      if (!allowPrivate && list.some(isBlockedIp)) {
        return callback(
          Object.assign(new Error(`SSRF: conexão recusada para ${hostname} → ${list.join(', ')}`), { code: 'ESSRFBLOCKED' }),
          undefined,
        )
      }
      callback(null, address, family)
    })
  }
}

/** undici Agent cujo connect valida o IP em cada conexão (inclui redirects). */
export function createSafeDispatcher(allowPrivate = false): Agent {
  return new Agent({
    connect: { lookup: makeValidatingLookup(allowPrivate) as never, timeout: 8_000 },
    headersTimeout: 10_000,
    bodyTimeout: 10_000,
  })
}

/**
 * Fábrica de clientes HTTP endurecidos: todo fetch passa pelo dispatcher
 * validador. `allowPrivate` só deve ser true em teste (fixtures em 127.0.0.1).
 */
export function createSafeClient(allowPrivate = false): (url: string) => FractaHttpClient {
  const dispatcher = createSafeDispatcher(allowPrivate)
  return (url: string) => new FractaHttpClient(url, {}, { dispatcher, redirect: 'follow' })
}
