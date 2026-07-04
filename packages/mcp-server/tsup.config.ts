import { defineConfig } from 'tsup'

/**
 * O MCP server é publicado no npm como binário SELF-CONTAINED (igual ao CLI):
 * os pacotes @fracta/* são embutidos (noExternal). Deps reais de npm ficam externas
 * (@modelcontextprotocol/sdk, yaml, undici). Resultado: `npx fractascan-mcp`
 * roda o servidor stdio sem clonar o monorepo.
 */
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm'],
  dts: false,
  clean: true,
  target: 'node20',
  noExternal: [/^@fracta\//],
  // `@fracta/verify` carrega o Chromium via `await import('playwright')` em runtime
  // (opcional — ausência degrada com BrowserUnavailableError). O pacote `playwright`
  // não pode ser bundlado: seu `playwright-core` tem requires condicionais (ex.:
  // chromium-bidi) que só existem quando o browser é instalado, e travam o esbuild
  // em build-time. Mantém externo; resolvido do node_modules em runtime, se presente.
  external: ['playwright', 'playwright-core'],
})
