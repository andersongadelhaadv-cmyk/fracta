import { defineConfig } from 'tsup'

/**
 * O MCP server é publicado no npm como binário SELF-CONTAINED (igual ao CLI):
 * os pacotes @fracta/* são embutidos (noExternal). Deps reais de npm ficam externas
 * (@modelcontextprotocol/sdk, yaml, undici). Resultado: `npx @fracta/mcp-server`
 * roda o servidor stdio sem clonar o monorepo.
 */
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm'],
  dts: false,
  clean: true,
  target: 'node20',
  noExternal: [/^@fracta\//],
})
