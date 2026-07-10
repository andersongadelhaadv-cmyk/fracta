# Auditabilidade das dependências

**Pergunta do cético:** "Se o CLI/MCP EMBUTEM (`tsup`) o código no `dist`, um `npm audit` no pacote
instalado enxerga a árvore de dependências?"

**Resposta honesta:** parcialmente. O bundle embute o código `@fracta/*` e algumas deps transitivas
(ex.: `undici`, via `@fracta/web-scan`) direto no `dist` — essas **não** aparecem num `npm audit` do
pacote instalado. As deps declaradas no `package.json` publicado (`yaml`, `@modelcontextprotocol/sdk`,
`undici` no MCP) **aparecem**. A superfície de terceiros é pequena por design: a maioria dos agentes
tem **zero deps** (fazem shell-out para `gitleaks`/`semgrep`/`npm` como binários externos) e usam só
APIs `node:` builtin.

**Decisão (2026-07-10): auditar a ÁRVORE na FONTE + publicar SBOM** — em vez de desbundlar.
Desbundlar quebraria o UX zero-config do `npx fractascan` (o motivo de embutir é rodar sem instalar uma
árvore). Então a auditoria acontece onde o `pnpm-lock.yaml` é a **verdade completa**: no CI.

O que o CI faz (job `deps-audit` em `.github/workflows/ci.yml`):
1. **`pnpm audit` da árvore completa** (incl. devDeps do toolchain) → relatório `pnpm-audit.json` como
   artefato, para transparência total.
2. **Gate honesto:** reprova só em **CRITICAL de produção** (`pnpm audit --prod --audit-level=critical`).
   CVE crítico no toolchain de build (ex.: `esbuild` dev-server, `GHSA-g7r4-m6w7-qqqr`) **não é
   embarcado** no pacote nem no runtime — reprovar nele seria cry-wolf. Deps de produção do
   CLI/MCP hoje: **0 critical**.
3. **SBOM CycloneDX** (`sbom.cdx.json`, via `cdxgen`) — **enumera cada dependência, inclusive as
   embutidas no bundle**. É o artefato que fecha o gap: quem quer a lista completa a tem, verificável.

**Como um cético verifica:**
- Baixe o artefato `fracta-deps-audit-sbom` de qualquer run do CI → `sbom.cdx.json` lista tudo.
- Ou rode você mesmo, na fonte: `pnpm install --frozen-lockfile && pnpm audit --prod`.
- Ou no pacote publicado: `npm i fractascan && npm audit` (cobre as deps declaradas; o SBOM cobre o resto).

**Ressalva honesta pendente:** o SBOM/CI enumera e audita a árvore, mas a auditoria do pacote instalado
via `npm audit` continua parcial para as deps embutidas — mitigada pela superfície mínima (undici é a
principal) e pelo SBOM. Bump de `next` (apps/web) é rastreado à parte (é o site, não o scanner).
