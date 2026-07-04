import { lookup } from 'node:dns/promises'
import { SsrfError } from './errors.js'

/** IPv4/IPv6 privados, loopback, link-local, unique-local, CGNAT e IPv4-mapeado-em-IPv6. */
export function isPrivateIp(ipRaw: string): boolean {
  const ip = ipRaw.toLowerCase().trim()
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') return true
  if (ip.startsWith('fc') || ip.startsWith('fd')) return true // unique-local fc00::/7
  if (/^fe[89ab]/.test(ip)) return true                        // link-local fe80::/10
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)      // IPv4-mapped IPv6
  if (mapped) return isPrivateIp(mapped[1])
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
  if (!m) return false
  const [a, b] = [Number(m[1]), Number(m[2])]
  if (a === 127 || a === 10 || a === 0) return true
  if (a === 169 && b === 254) return true                      // link-local
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true            // CGNAT 100.64/10
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

/**
 * Decisão por-requisição para o interceptor do browser: o host da URL é público?
 * Fecha SSRF por redirect/subrecurso (o guard inicial só cobre o host inicial).
 * Fail-closed: URL inválida ou host privado → false.
 */
export async function isRequestHostAllowed(
  url: string,
  opts: { allowPrivate?: boolean; resolver?: Resolver } = {},
): Promise<boolean> {
  if (opts.allowPrivate) return true
  let host: string
  try {
    host = new URL(url).hostname
  } catch {
    return false
  }
  try {
    await assertPublicHost(host, { resolver: opts.resolver })
    return true
  } catch {
    return false
  }
}
