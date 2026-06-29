import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))

/** Headers de segurança da própria home — o Fracta não pode falhar o próprio scan (dogfood). */
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
]

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  reactStrictMode: true,
  experimental: {
    // Monorepo: rastreia deps de workspace a partir da raiz p/ o standalone.
    outputFileTracingRoot: join(__dirname, '../../'),
    // Mantém o motor (node:sqlite/dns + undici) como módulo Node real no servidor — nunca bundlado.
    serverComponentsExternalPackages: ['@fracta/web-scan', '@fracta/core', '@fracta/agent-headers', 'undici'],
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}

export default nextConfig
