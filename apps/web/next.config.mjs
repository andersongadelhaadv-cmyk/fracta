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

/**
 * `output: 'standalone'` monta o bundle criando SYMLINKS. No Windows, `fs.symlink` exige
 * SeCreateSymbolicLinkPrivilege (admin ou Developer Mode) → EPERM, e o `pnpm build` local
 * morre no passo de file-tracing (#35). Linux/CI/Docker não são afetados.
 *
 * O Dockerfile COPIA `.next/standalone`, então o standalone TEM que continuar sendo o
 * padrão. Por isso o desligamento é fail-safe e cirúrgico: só no Windows FORA de CI.
 * O caminho de produção segue idêntico e não depende de ninguém lembrar de setar env var
 * (o inverso — exigir uma flag p/ ligar o standalone — quebraria o Docker no primeiro
 * esquecimento).
 *
 * Para testar o bundle standalone no Windows: ligue o Developer Mode e rode com
 * FRACTA_FORCE_STANDALONE=1.
 */
const isWindowsLocal = process.platform === 'win32' && !process.env.CI
const useStandalone = !isWindowsLocal || !!process.env.FRACTA_FORCE_STANDALONE

/** @type {import('next').NextConfig} */
const nextConfig = {
  ...(useStandalone ? { output: 'standalone' } : {}),
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
