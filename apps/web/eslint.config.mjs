// ESLint 9+ só lê flat config, e o `next lint` — que carregava o `.eslintrc.json` —
// foi removido no Next 16. Mesmo conjunto de regras de antes (`next/core-web-vitals`),
// no formato novo, agora invocado direto pela CLI do ESLint (`eslint .`).
import coreWebVitals from 'eslint-config-next/core-web-vitals'

const config = [
  { ignores: ['.next/**', 'next-env.d.ts'] },
  ...coreWebVitals,
]

export default config
