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

function isBlockedV4Int(v4: number): boolean {
  return V4_BLOCKED.some((c) => inV4(v4, c))
}

/**
 * Faz parse de um literal IPv6 em 16 bytes. Trata compressão `::`, IPv4 embutido
 * (`::ffff:1.2.3.4`), zone-id e formas expandidas. Retorna null se não for IPv6.
 */
function parseIPv6(input: string): number[] | null {
  let str = input.toLowerCase().trim()
  const zone = str.indexOf('%')
  if (zone !== -1) str = str.slice(0, zone)
  if (str.indexOf(':') === -1) return null

  // IPv4 embutido no fim (ex.: ::ffff:127.0.0.1)
  let v4groups: number[] = []
  const m = str.match(/(\d{1,3}(?:\.\d{1,3}){3})$/)
  if (m && m.index !== undefined) {
    const v4 = ipv4ToInt(m[1])
    if (v4 === null) return null
    v4groups = [(v4 >>> 16) & 0xffff, v4 & 0xffff]
    str = str.slice(0, m.index) // sobra o ':' separador antes do v4
    // remove o ':' separador residual, mas preserva o '::' de compressão
    if (str.endsWith(':') && !str.endsWith('::')) str = str.slice(0, -1)
  }

  const dbl = str.indexOf('::')
  const headPart = dbl !== -1 ? str.slice(0, dbl) : str
  const tailPart = dbl !== -1 ? str.slice(dbl + 2) : ''

  const toGroups = (part: string): number[] | null => {
    if (!part) return []
    const out: number[] = []
    for (const g of part.split(':')) {
      if (g === '' || !/^[0-9a-f]{1,4}$/.test(g)) return null
      out.push(parseInt(g, 16))
    }
    return out
  }

  const head = toGroups(headPart)
  const tail = toGroups(tailPart)
  if (head === null || tail === null) return null

  const provided = head.length + tail.length + v4groups.length
  let full: number[]
  if (dbl !== -1) {
    const zeros = 8 - provided
    if (zeros < 0) return null
    full = [...head, ...Array(zeros).fill(0), ...tail, ...v4groups]
  } else {
    full = [...head, ...tail, ...v4groups]
  }
  if (full.length !== 8) return null

  const bytes: number[] = []
  for (const g of full) bytes.push((g >>> 8) & 0xff, g & 0xff)
  return bytes
}

function allZero(bytes: number[], from: number, to: number): boolean {
  for (let i = from; i < to; i++) if (bytes[i] !== 0) return false
  return true
}

function isBlockedV6Bytes(b: number[]): boolean {
  // loopback ::1 e unspecified ::
  if (allZero(b, 0, 15) && (b[15] === 0 || b[15] === 1)) return true
  // link-local fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true
  // ULA fc00::/7 (inclui fd00::/8, AWS IMDS v6 fd00:ec2::254)
  if ((b[0] & 0xfe) === 0xfc) return true
  // multicast ff00::/8
  if (b[0] === 0xff) return true
  const embeddedV4 = (i: number) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0
  // IPv4-mapeado ::ffff:a.b.c.d  e  IPv4-compatível ::a.b.c.d (deprecado)
  if (allZero(b, 0, 10) && ((b[10] === 0xff && b[11] === 0xff) || (b[10] === 0 && b[11] === 0))) {
    return isBlockedV4Int(embeddedV4(12))
  }
  // NAT64 64:ff9b::/96
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && allZero(b, 4, 12)) {
    return isBlockedV4Int(embeddedV4(12))
  }
  // 6to4 2002::/16 (v4 nos bytes 2–5)
  if (b[0] === 0x20 && b[1] === 0x02) {
    return isBlockedV4Int(embeddedV4(2))
  }
  return false
}

/**
 * true = IP que NUNCA deve ser escaneado (interno/privado/reservado/metadata).
 * Cobre IPv4 (CIDRs) e IPv6 com parser real — incluindo formas mapeadas hex
 * (`::ffff:7f00:1`), NAT64 e 6to4 que embutem um IPv4 interno.
 */
export function isBlockedIp(ip: string): boolean {
  const v4 = ipv4ToInt(ip)
  if (v4 !== null) return isBlockedV4Int(v4)
  const bytes = parseIPv6(ip)
  if (bytes) return isBlockedV6Bytes(bytes)
  return false // não é IP literal — hostnames são tratados via resolução
}

export type AddressResolver = (host: string) => Promise<string[]>

const defaultResolver: AddressResolver = async (host) => {
  const records = await lookup(host, { all: true })
  return records.map((r) => r.address)
}

/** Portas de serviços internos comuns — bloqueadas mesmo em IP público (anti-recon). */
const BLOCKED_PORTS = new Set([
  22, 23, 25, 135, 139, 445, 1433, 1521, 2049, 2375, 2379, 3306, 3389,
  5432, 5984, 6379, 9200, 9300, 11211, 27017,
])

/**
 * Valida uma URL de scan ANTES de qualquer fetch. Sem esquema → assume https.
 * Recusa: esquema != http/https; credenciais embutidas (userinfo); porta de
 * serviço interno; host que resolve (ou é literal) p/ IP interno; host sem
 * endereço resolvível. Lança SsrfError. Resolver injetável p/ teste.
 *
 * NOTA: a defesa contra obfuscação IPv4 (decimal/octal/hex) depende da
 * normalização do `dns.lookup` (literais como 2130706433 viram 127.0.0.1 e caem
 * na checagem pós-resolução). Trocar o resolver por `dns.resolve*` quebraria isso.
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
  if (url.username || url.password) {
    throw new SsrfError('Credenciais embutidas na URL não são permitidas')
  }
  if (url.port && BLOCKED_PORTS.has(Number(url.port))) {
    throw new SsrfError(`Porta não permitida: ${url.port} (serviço interno)`)
  }
  if (url.hostname.length > 253) {
    throw new SsrfError('Hostname longo demais')
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
