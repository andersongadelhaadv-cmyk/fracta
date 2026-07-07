import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Os testes *.browser.test.ts lançam Chromium (via playwright). Rodar os 4
    // arquivos em paralelo (default do vitest) lança 4 browsers ao mesmo tempo e,
    // sob carga — ex.: `turbo test --force`, que a memória recomenda como padrão —,
    // um deles estoura o timeout por contenção de recursos (visto em 45–96s vs ~4s
    // isolado). Serializar os ARQUIVOS garante ≤1 Chromium por vez → elimina a
    // contenção POR CONSTRUÇÃO. Os arquivos não-browser são de ms; o custo é nulo.
    fileParallelism: false,
  },
})
