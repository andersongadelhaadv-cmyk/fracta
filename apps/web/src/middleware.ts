import { NextResponse, type NextRequest } from 'next/server'

/**
 * Content-Security-Policy com NONCE por request (padrão Next.js app router).
 *
 * Por que nonce e não `'unsafe-inline'`: o próprio scanner do Fracta (HeadersAgent)
 * trata `script-src 'unsafe-inline'` como HIGH — CSP-teatro que anula a proteção
 * contra XSS. Dogfood honesto: a home não pode fazer o que condena. O nonce autoriza
 * só os scripts inline legítimos do Next (hidratação), sem abrir a porta pro injetado.
 *
 * `style-src 'unsafe-inline'` fica (next/font + estilos inline do Next não recebem
 * nonce de forma confiável) — no scanner isso é `info` (peso 0), não derruba a nota.
 * O `<script type="application/ld+json">` é data block: a spec do CSP não o submete a
 * script-src (não é executado), então dispensa nonce.
 */
export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64')

  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data:`,
    `font-src 'self' data:`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'self'`,
    `upgrade-insecure-requests`,
  ].join('; ')

  // Setar o CSP no header do REQUEST é o que faz o Next propagar o nonce aos seus
  // próprios <script> (hidratação/chunks). O mesmo nonce vai no header da RESPOSTA
  // (o que o browser impõe) — precisam bater.
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('content-security-policy', csp)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  response.headers.set('content-security-policy', csp)
  return response
}

export const config = {
  // Aplica a tudo, exceto assets estáticos e a API (CSP só faz sentido no HTML).
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|icon.svg|apple-icon.png|brand|robots.txt|sitemap.xml|manifest.webmanifest).*)',
  ],
}
