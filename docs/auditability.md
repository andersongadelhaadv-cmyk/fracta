# Auditabilidade das dependências

**Pergunta do cético:** "Se o CLI/MCP EMBUTEM (`tsup`) o código no `dist`, um `npm audit` no pacote
instalado enxerga a árvore de dependências?"

**Resposta honesta (MEDIDA, não presumida — 2026-07-10):** sim, na prática toda. Medimos o que de fato
é embutido, em vez de supor:

- O bundle embute o código `@fracta/*` (workspace) — e esses pacotes têm **superfície de terceiros
  quase nula**: a maioria dos agentes tem **zero deps** (fazem shell-out para `gitleaks`/`semgrep`/`npm`
  como binários externos) e usam só APIs `node:` builtin.
- **`yaml`** — declarado no `package.json` do CLI e do MCP → `npm audit` **vê**.
- **`undici`** — usado só pelo `@fracta/web-scan` (scanner passivo). NÃO é embutido no CLI (medido:
  0 referências no bundle; o CLI não usa o caminho passivo). No **MCP** é **dependência declarada** →
  `npm audit` **vê**.
- **`@anthropic-ai/sdk`** — borda LLM **opt-in** (zero-token por padrão). Carregado por `import()`
  **dinâmico** (não é embutido; o bundle do CLI tem 232 KB, não os MBs do SDK). Agora **declarado como
  `peerDependency` opcional** no CLI/MCP → é superfície explícita e auditável, sem inflar o `npx`
  padrão (só instala se o usuário optar). Ausente → erro claro capturado e **degrada** para o relatório
  determinístico (nunca derruba o scan).

**Ou seja: não há dep de terceiros "embutida e invisível" de valor.** O que o bundle inlina é o código
`@fracta/*`, cujo próprio grafo de terceiros é mínimo e declarado onde importa.

## Prova contínua no CI (job `deps-audit`)
1. **`pnpm audit` da árvore completa** (incl. devDeps do toolchain) → relatório `pnpm-audit.json` como
   artefato.
2. **Gate honesto:** reprova só em **CRITICAL de PRODUÇÃO** (`pnpm audit --prod --audit-level=critical`).
   CVE crítico no toolchain de build (ex.: `esbuild` dev-server) **não é embarcado** — reprovar nele
   seria cry-wolf. Deps de produção do CLI/MCP: **0 critical**.
3. **SBOM CycloneDX** (`sbom.cdx.json`, via `cdxgen`) — **enumera cada dependência**. É a lista completa,
   verificável, para quem quiser além do `npm audit`.

## Como um cético verifica
- Na fonte: `pnpm install --frozen-lockfile && pnpm audit --prod`.
- No pacote publicado: `npm i fractascan && npm audit` — cobre as deps declaradas (yaml; +undici/mcp-sdk
  no MCP; +anthropic se optar por `--llm`).
- Lista completa: baixe o artefato `fracta-deps-audit-sbom` de qualquer run do CI → `sbom.cdx.json`.

**Decisão de design (por que NÃO desbundlar):** desbundlar o `@fracta/*` quebraria o UX zero-config do
`npx fractascan` (o motivo de embutir é rodar sem instalar a árvore do workspace). Como a medição mostrou
que **nada de terceiros relevante é inlinado**, desbundlar não traria ganho de auditabilidade real — só
custo. A auditoria fica na fonte (lockfile = verdade) + SBOM no CI.

**Ressalva pendente (menor) — DECISÃO DE ADIAR, com motivo:** `next@14.2.35` (do `apps/web`, o **site** —
não o CLI/MCP que o usuário instala) tem CVEs `low`/`moderate` cujo patch só existe no **Next 15**
(14.2.35 é o último 14.x). Isso é uma **migração de major** (async request APIs, semântica de cache,
breaking do App Router) que pode quebrar o site LIVE (fracta.pro). Um sênior NÃO faz major-bump de
framework de arrasto: a severidade é baixa e no site, não no scanner. Fica como tarefa própria,
testada — não paga a dívida com um risco maior que a dívida.
