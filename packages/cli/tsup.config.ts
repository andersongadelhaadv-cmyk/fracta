import { defineConfig } from 'tsup'

/**
 * O CLI é publicado no npm como um binário SELF-CONTAINED: os pacotes de workspace
 * (@fracta/*) são embutidos no bundle (noExternal), porque `workspace:*` não resolve
 * fora do monorepo. Só deps reais de npm (yaml) + builtins do Node ficam externos.
 * Resultado: `npx @fracta/cli` funciona sem clonar o repo.
 */
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm'],
  dts: false, // binário CLI não precisa publicar tipos
  clean: true,
  target: 'node20',
  noExternal: [/^@fracta\//],
  // yaml e builtins (node:sqlite, node:dns, child_process…) permanecem externos.
})
