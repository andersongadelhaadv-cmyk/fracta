import { lookup } from 'node:dns/promises'
import { SsrfError } from './errors.js'

/** IPv4/IPv6 privados, loopback e link-local. */
export function isPrivateIp(ip: string): boolean {
  if (ip === '::1' || ip.startsWith('fe80') || ip.startsWith('fc') || ip.startsWith('fd')) return true
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
  if (!m) return false
  const [a, b] = [Number(m[1]), Number(m[2])]
  if (a === 127 || a === 10 || a === 0) return true
  if (a === 169 && b === 254) return true // link-local
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  return false
}

type Resolver = (host: string) => Promise<string[]>

const defaultResolver: Resolver = async (host) => {
  const records = await lookup(host, { all: true })
  return records.map((r) => r.address)
}

/**
 * Bloqueia navegação para hosts internos ANTES do goto. Honestidade: o browser
 * não valida IP por-conexão como o dispatcher do passive; este guard é a primeira
 * linha, e `verify` é para alvos que você controla/autoriza.
 */
export async function assertPublicHost(
  hostname: string,
  opts: { allowPrivate?: boolean; resolver?: Resolver } = {},
): Promise<void> {
  if (opts.allowPrivate) return
  const resolver = opts.resolver ?? defaultResolver
  let ips: string[]
  try {
    ips = await resolver(hostname)
  } catch {
    throw new SsrfError(`Não consegui resolver o host: ${hostname}`)
  }
  if (ips.some(isPrivateIp)) {
    throw new SsrfError(`Host resolve para IP privado/interno — recusado: ${hostname}`)
  }
}
