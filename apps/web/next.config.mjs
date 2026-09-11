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
  /**
   * 🔴 MITIGAÇÃO DE CVE CRÍTICO — não é preferência de performance.
   *
   * next@14.2.35 tem RCE NÃO AUTENTICADO na Image Optimization API quando o
   * otimizador decodifica um AVIF (GHSA-p293-qw3h-jr36). Não existe correção na
   * linha 14.x: a 14.2.35 é a última publicada e a Vercel não fez backport — a
   * versão corrigida é a 15.5.24, que é salto de major (React 19, `await params`).
   *
   * `unoptimized: true` não é cosmético aqui: em
   * `next/dist/server/next-server.js:167` o handler de `/_next/image` faz
   *
   *     if (imagesConfig.loader !== "default" || imagesConfig.unoptimized) {
   *       await this.render404(req, res); return true;
   *     }
   *
   * ou seja, devolve 404 ANTES de `validateParams`, antes de buscar a imagem e
   * antes de qualquer decodificação. O caminho vulnerável deixa de existir.
   * (Verificado no código instalado em 10/09/2026, não na documentação.)
   *
   * Custo funcional: ZERO. Este app não importa `next/image` em lugar nenhum —
   * `<Image` aparece 0 vezes; a única ocorrência de "next/image" no código é o
   * padrão de exclusão `_next/image` do matcher em `src/middleware.ts:48`.
   *
   * ⚠️ REMOVER esta linha ao subir para >= 15.5.24, junto com o upgrade. Se
   * alguém passar a usar `next/image` antes disso, as imagens vão servir sem
   * otimização — e aí a conversa é o upgrade, não tirar a trava.
   */
  images: { unoptimized: true },
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
