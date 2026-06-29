import { lookup } from 'node:dns/promises'
import { SsrfError } from './types.js'

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const o = Number(p)
    if (o > 255) return null
    n = (n << 8) | o
  }
  return n >>> 0
}

function inV4(ip: number, cidr: string): boolean {
  const [base, bitsStr] = cidr.split('/')
  const bits = Number(bitsStr)
  const baseInt = ipv4ToInt(base)!
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (ip & mask) === (baseInt & mask)
}

const V4_BLOCKED = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
]

/** true = IP que NUNCA deve ser escaneado (interno/privado/reservado). Cobre v4 + v6 comuns. */
export function isBlockedIp(ip: string): boolean {
  const v4 = ipv4ToInt(ip)
  if (v4 !== null) return V4_BLOCKED.some((c) => inV4(v4, c))

  // IPv6 (normaliza minúsculas; trata mapeados ::ffff:1.2.3.4)
  const lower = ip.toLowerCase()
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  if (mapped) return isBlockedIp(mapped[1])
  if (lower === '::' || lower === '::1') return true
  if (lower.startsWith('fe80:')) return true // link-local
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true // fc00::/7 ULA
  return false
}

export type AddressResolver = (host: string) => Promise<string[]>

const defaultResolver: AddressResolver = async (host) => {
  const records = await lookup(host, { all: true })
  return records.map((r) => r.address)
}

/**
 * Valida uma URL de scan ANTES de qualquer fetch. Sem esquema → assume https.
 * Recusa: esquema != http/https; host que resolve (ou é literal) p/ IP interno;
 * host sem endereço resolvível. Lança SsrfError. Resolver injetável p/ teste.
 */
export async function validateScanUrl(
  input: string,
  opts: { resolve?: AddressResolver } = {},
): Promise<URL> {
  const resolve = opts.resolve ?? defaultResolver
  const raw = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`

  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new SsrfError(`URL inválida: ${input}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfError(`Esquema não permitido: ${url.protocol} (use http/https)`)
  }

  // host literal já bloqueado? (IPv6 literal vem entre colchetes na URL)
  const host = url.hostname.replace(/^\[|\]$/g, '')
  if (isBlockedIp(host)) {
    throw new SsrfError('Endereço interno/privado não é escaneável')
  }

  let addrs: string[]
  try {
    addrs = await resolve(host)
  } catch {
    throw new SsrfError(`Não foi possível resolver o host: ${host}`)
  }
  if (addrs.length === 0) {
    throw new SsrfError(`Host sem endereço resolvível: ${host}`)
  }
  if (addrs.some(isBlockedIp)) {
    throw new SsrfError('O host resolve para um endereço interno/privado — recusado')
  }
  return url
}
