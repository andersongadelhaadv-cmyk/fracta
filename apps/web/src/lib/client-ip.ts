import type { NextRequest } from 'next/server'

/** IP real do visitante atrás do nginx (que seta X-Forwarded-For / X-Real-IP). */
export function getClientIp(req: NextRequest): string {
  const xff = req.headers.get('x-forwarded-for')
  if (xff) {
    const first = xff.split(',')[0]?.trim()
    if (first) return first
  }
  return req.headers.get('x-real-ip')?.trim() || 'unknown'
}
