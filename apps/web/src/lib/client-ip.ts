import type { NextRequest } from 'next/server'

/**
 * IP real do visitante. Confia primeiro no `X-Real-IP` (o nginx o seta como
 * `$remote_addr`, o peer verdadeiro — não falsificável pelo cliente). O
 * `X-Forwarded-For` só é fallback: como o nginx usa `$proxy_add_x_forwarded_for`
 * (APPENDA ao XFF enviado pelo cliente), seu PRIMEIRO elemento é spoofável e não
 * deve ser a fonte da chave de rate-limit.
 */
export function getClientIp(req: NextRequest): string {
  const real = req.headers.get('x-real-ip')?.trim()
  if (real) return real
  const xff = req.headers.get('x-forwarded-for')
  if (xff) {
    // sem X-Real-IP confiável, o ÚLTIMO hop é o mais próximo do proxy de confiança
    const parts = xff.split(',').map((s) => s.trim()).filter(Boolean)
    if (parts.length) return parts[parts.length - 1]
  }
  return 'unknown'
}
