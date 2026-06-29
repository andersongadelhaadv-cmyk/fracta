# Fracta.pro — `apps/web` (Home autoral + Scanner passivo) — Implementation Plan (Plano 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development ou superpowers:executing-plans. Steps usam checkbox (`- [ ]`).

**Goal:** Construir `apps/web` (Next.js App Router) — a home autoral do fracta.pro com scanner web passivo end-to-end: URL → SSRF guard → HEADERS+TLS+cookies+LGPD-lite → nota A–F → página `/r/[shareId]` compartilhável → captura de e-mail. Reusa `@fracta/web-scan` (Plano 1), zero reimplementação de detecção.

**Architecture:** Next.js 14 (App Router, React 18, output `standalone`) + Tailwind v3 + TypeScript, como `apps/web` no monorepo pnpm/turbo. Todo o motor roda **só no servidor** (route handlers `runtime = 'nodejs'`): o engine importa `node:dns/sqlite/net` e NUNCA pode ir pro client. Persistência via `SqliteScanStore` singleton (path por env, volume na VPS). SSRF guard + rate-limit + cache na frente de todo scan. A home é dirigida a prova: o herói renderiza um relatório real.

**Tech Stack:** Next.js 14.2, React 18, Tailwind 3.4, TypeScript 5, `@fracta/web-scan` (workspace:*). Node ≥22.5 (node:sqlite).

---

## DNA visual (fonte da verdade de design — não "landing de IA genérica")

**Princípio:** mostrar, não contar. O produto (o relatório real) É o marketing. Menos copy, mais prova. Honestidade como linguagem visual: um check que não rodou aparece **"não verificado"** (cinza, tracejado) — JAMAIS verde.

**Tokens (CSS variables em `globals.css`):**
- Fundo: `--bg: #0a0b0d` (quase-preto, leve tint frio); superfície elevada `--surface: #121417`; superfície 2 `--surface-2: #15181c`; borda `--border: #1f2329`; borda-forte `--border-strong: #2b3038`.
- Texto: `--text: #e7e9ec`; `--muted: #8b9299`; `--faint: #5b636b`.
- **Acento de marca (ÚNICO, disciplinado): ciano-instrumento `--accent: #3ad6cf`** (+ `--accent-dim: #1c6f6b`). Usado só em: cursor/foco, o ponto do logo, links, a "scanline" do herói, 1 CTA. NÃO é roxo/rosa, NÃO é gradiente.
- **Escala semântica de nota (legenda forense, SEPARADA do acento)** — só nos badges/anéis de nota: `A #34d399` · `B #a3e635` · `C #facc15` · `D #fb923c` · `E #f87171` · `F #ef4444`. Cinza `--faint` para **não verificado**.
- Severidade (findings): critical `#ef4444` · high `#fb923c` · medium `#facc15` · low `#8b9299` · info `--faint`.

**Tipografia:** prosa em grotesk limpa (Geist Sans ou Inter via `next/font`); **todo dado/evidência/URL/header em monospace** (Geist Mono ou JetBrains Mono). Mono é a textura da marca.

**Layout/anti-clichê:** sem glassmorphism, sem blobs, sem gradiente roxo→rosa, sem emoji decorativo, sem ilustração stock, sem "Features" 3-colunas. Profundidade vem de borda 1px + elevação sutil de superfície, não de sombra borrada. Cantos levemente arredondados (4–6px), nunca pílulas. Grid apertado, hairlines.

**Seções da home (autorais):**
1. **Herói** — esquerda: wordmark `fracta` (ponto ciano), headline técnica PT-BR + subhead honesta + **caixa de scan** (input mono grande, placeholder `https://seusaas.com.br`, botão "Analisar"); linha de confiança ("Detecção determinística · sem cadastro · grátis"). Direita: **um relatório-amostra REAL renderizado** (anel de nota, 4–5 headers com ✓/✗ reais, 1 linha de evidência sanitizada em mono, e 1 check em "não verificado" mostrando a honestidade). Em mobile, empilha.
2. **Como funciona** — pipeline horizontal em mono/monoespaçado: `URL → SSRF guard → HEADERS · TLS · cookies · LGPD-lite → nota A–F → link compartilhável`. Técnico, não decorativo.
3. **O que medimos (e o que NÃO medimos)** — duas colunas honestas. *Medimos:* security headers, TLS/HTTPS, flags de cookie, LGPD-lite (beta). *Não medimos:* sem login/ataque ativo, sem "100% seguro", ausência de achado ≠ seguro. Este é o diferencial anti-genérico.
4. **Por que confiar** — cruzamento: determinístico (sem alucinação de IA, mesmo motor do CLI open-source) + LGPD/autoridade jurídica (dono advogado, frota legaltech) + repo público auditado. Números reais da frota.
5. **ZapApiSupporter** — banner "ecossistema" discreto (ZAP-API), nunca CTA principal.
6. **Footer** — repo GitHub, nota LGPD, "feito no Brasil".

---

## File Structure

```
apps/web/
  package.json            # @fracta/web (private), next 14.2, dep @fracta/web-scan workspace:*
  next.config.mjs         # output: 'standalone'; headers() endurecendo a própria home (HSTS etc.)
  tailwind.config.ts
  postcss.config.mjs
  tsconfig.json
  .eslintrc.json
  src/
    app/
      layout.tsx          # fonts (next/font), metadata/OG, <body> dark
      globals.css         # tokens (CSS vars) + base Tailwind
      page.tsx            # Home (server component) — compõe as seções
      r/[shareId]/page.tsx# resultado SSR compartilhável (lê store por shareId)
      api/
        scan/route.ts     # POST: SSRF guard + rate-limit + cache + scan + store → { shareId }
        email/route.ts    # POST: captura e-mail
        badge/[shareId]/route.ts # GET: SVG dinâmico da nota (SEO/viralização)
    lib/
      scan-store.ts       # singleton SqliteScanStore (path por env, degradação graciosa)
      rate-limit.ts       # singleton InMemoryRateLimiter (10/10min)
      client-ip.ts        # extrai IP do request (x-forwarded-for atrás do nginx)
      config.ts           # constantes: CACHE_TTL_MS, RATE_LIMIT, etc.
    components/
      ScanForm.tsx        # 'use client' — input + submit → POST /api/scan → router.push(/r/id)
      ReportView.tsx      # render do PassiveScanResult (anel de nota + findings + honestidade)
      GradeRing.tsx       # anel A–F (SVG), cor da escala semântica
      FindingRow.tsx      # 1 finding (severidade, título, evidência mono, recomendação)
      Honesty.tsx         # callout "não verificado"/inconclusivo
      EmailCapture.tsx    # 'use client' — POST /api/email
      ZapApiSupporter.tsx # banner discreto
      Pipeline.tsx        # diagrama "como funciona"
      Wordmark.tsx        # logo fracta (ponto ciano)
      SampleReport.tsx    # dados-amostra reais (estáticos) p/ o herói
```

**pnpm-workspace.yaml:** adicionar `- 'apps/*'`. **turbo.json:** o build do Next gera `.next/**`; adicionar outputs ao task `build` (ou deixar o Next fora do cache — ver Task 1).

---

## Task 1: Scaffold `apps/web` no monorepo

**Files:** criar `apps/web/{package.json,next.config.mjs,tsconfig.json,tailwind.config.ts,postcss.config.mjs,.eslintrc.json}`; modificar `pnpm-workspace.yaml`, `turbo.json`.

- [ ] **Step 1: `pnpm-workspace.yaml`** — adicionar `- 'apps/*'` à lista de packages.
- [ ] **Step 2: `apps/web/package.json`**

```json
{
  "name": "@fracta/web",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "next dev -p 3850",
    "build": "next build",
    "start": "next start -p 3850",
    "lint": "next lint",
    "test": "vitest run --passWithNoTests"
  },
  "dependencies": {
    "@fracta/web-scan": "workspace:*",
    "next": "14.2.5",
    "react": "18.3.1",
    "react-dom": "18.3.1"
  },
  "devDependencies": {
    "@types/node": "*", "@types/react": "18.3.3", "@types/react-dom": "18.3.0",
    "autoprefixer": "^10.4.0", "postcss": "^8.4.0", "tailwindcss": "^3.4.0",
    "typescript": "*", "eslint": "^8", "eslint-config-next": "14.2.5", "vitest": "*"
  }
}
```

- [ ] **Step 3: `next.config.mjs`** — `output: 'standalone'`, `poweredByHeader: false`, `transpilePackages: ['@fracta/web-scan']` (para o Next compilar o workspace ESM), e `headers()` aplicando à própria home HSTS/X-Content-Type-Options/X-Frame-Options/Referrer-Policy/Permissions-Policy (Fracta não pode falhar o próprio scan — dogfood). `experimental.serverComponentsExternalPackages: ['@fracta/web-scan','@fracta/core','@fracta/agent-headers']` para não bundlar o motor (mantém `node:sqlite`/`node:dns` no servidor).
- [ ] **Step 4: `tsconfig.json`** — preset Next (`jsx: preserve`, `moduleResolution: bundler`, paths `@/*` → `src/*`). NÃO estende o tsconfig raiz (Next tem o seu).
- [ ] **Step 5: `tailwind.config.ts`** — `content: ['./src/**/*.{ts,tsx}']`; estender `colors` com os tokens via `var(--...)`; `fontFamily` sans/mono apontando às CSS vars do `next/font`.
- [ ] **Step 6: `postcss.config.mjs`** (tailwind+autoprefixer), `.eslintrc.json` (`next/core-web-vitals`).
- [ ] **Step 7: `turbo.json`** — no task `build`, adicionar `"outputs": ["dist/**", ".next/**", "!.next/cache/**"]`.
- [ ] **Step 8:** `pnpm install`. Confirmar que resolve `@fracta/web` e linka `@fracta/web-scan`.
- [ ] **Step 9: Commit** `chore(web): scaffold apps/web (Next 14 App Router + Tailwind)`.

---

## Task 2: Design tokens + layout base (RED→GREEN visual)

**Files:** criar `src/app/globals.css`, `src/app/layout.tsx`, `src/components/Wordmark.tsx`.

- [ ] **Step 1: `globals.css`** — `@tailwind base/components/utilities` + `:root` com TODOS os tokens do DNA acima (cores, escala de nota, severidade). Base: `body { background: var(--bg); color: var(--text) }`. Utilitário `.scanline` (linha ciano sutil animada no herói, `prefers-reduced-motion` respeitado).
- [ ] **Step 2: `layout.tsx`** — `next/font` (Geist Sans + Geist Mono ou Inter+JetBrains Mono) expostos como CSS vars; `<html lang="pt-BR" class="dark">`; metadata completa (title, description PT-BR, OpenGraph com imagem, `metadataBase`). `<body>` aplica as fontes.
- [ ] **Step 3: `Wordmark.tsx`** — `fracta` em mono-medium com o ponto final em `--accent`.
- [ ] **Step 4:** smoke visual — `pnpm --filter @fracta/web dev`, abrir, confirmar fundo escuro + fontes carregam, zero erro de console.
- [ ] **Step 5: Commit** `feat(web): design tokens + layout base`.

---

## Task 3: Engine glue — store, rate-limit, ip, config (server-only)

**Files:** criar `src/lib/{config.ts,scan-store.ts,rate-limit.ts,client-ip.ts}`.

- [ ] **Step 1: `config.ts`**

```ts
export const CACHE_TTL_MS = 60 * 60 * 1000           // 1h
export const RATE_LIMIT = { limit: 10, windowMs: 10 * 60 * 1000 } // 10 scans / 10min por IP
export const DB_PATH = process.env.FRACTA_WEB_DB ?? './fracta-web.db'
export const SCAN_TIMEOUT_MS = 12_000
```

- [ ] **Step 2: `scan-store.ts`** — singleton com degradação graciosa: tenta `new SqliteScanStore(DB_PATH)`; se `node:sqlite` indisponível, loga aviso e expõe um store no-op (scan ainda roda, só não persiste/compartilha). Usa `globalThis` p/ sobreviver ao HMR do dev.

```ts
import { SqliteScanStore } from '@fracta/web-scan'
import { DB_PATH } from './config'
type Store = SqliteScanStore | null
const g = globalThis as unknown as { __fractaStore?: Store }
export function getStore(): Store {
  if (g.__fractaStore !== undefined) return g.__fractaStore
  try { g.__fractaStore = new SqliteScanStore(DB_PATH) }
  catch (e) { console.warn('[fracta-web] store indisponível, seguindo sem persistência:', (e as Error).message); g.__fractaStore = null }
  return g.__fractaStore
}
```

- [ ] **Step 3: `rate-limit.ts`** — singleton `InMemoryRateLimiter(RATE_LIMIT)` via `globalThis`.
- [ ] **Step 4: `client-ip.ts`** — lê `x-forwarded-for` (primeiro IP) / `x-real-ip` do `Request.headers`; fallback `'unknown'`. (nginx seta esses.)
- [ ] **Step 5:** sem teste unitário aqui (glue de integração; o motor já é testado). Commit `feat(web): server glue — store/rate-limit/ip singletons`.

---

## Task 4: Scan API (`POST /api/scan`) — SSRF + rate-limit + cache + store

**Files:** criar `src/app/api/scan/route.ts`. **Test:** `src/app/api/scan/__tests__/route.test.ts`.

- [ ] **Step 1: teste** (vitest, chamando o handler com `Request` fabricado): (a) URL interna `http://169.254.169.254` → 400 com mensagem de recusa; (b) URL inválida → 400; (c) acima do rate-limit → 429; (d) URL pública benigna mockada → 200 com `{ shareId }`. Mockar `PassiveScanner.scan` e `validateScanUrl` via injeção/spy onde necessário (ou testar só os ramos de guarda/limite com a engine real apontando a um fixture local).
- [ ] **Step 2: implementar `route.ts`** (`export const runtime = 'nodejs'`): ler `{ url }` do body → `getClientIp` → `rateLimiter.check(ip)` (429 se bloqueado) → `validateScanUrl(url)` (SsrfError → 400 recusa explícita) → `store.getCached(normalizedUrl, CACHE_TTL_MS)` (hit → retorna shareId existente OU re-salva) → senão `new PassiveScanner().scan(url)` → `store.save(result)` → `{ shareId, grade, verdict }`. Erros do scan → 502 com veredito honesto (nunca "seguro"). Tudo try/catch; nunca vaza stack.
- [ ] **Step 3:** rodar testes (GREEN). **Step 4: Commit** `feat(web): scan API com SSRF guard + rate-limit + cache`.

> **PRÉ-REQUISITO DE SEGURANÇA (do review do Plano 1):** antes de expor publicamente, endurecer o motor contra **SSRF por redirect** (o `fetch` segue 302 por padrão → pode pular pra IP interno) e considerar **DNS rebinding/TOCTOU**. Se o review confirmar o furo, adicionar tarefa de hardening no `@fracta/web-scan` (redirect manual + revalidação do destino) e SÓ então ligar a caixa de scan. Se não fechar com segurança nesta sessão → home + waitlist, scan "beta/em breve", SEM caixa sem guard.

---

## Task 5: Componentes de relatório — GradeRing, FindingRow, Honesty, ReportView

**Files:** criar `src/components/{GradeRing,FindingRow,Honesty,ReportView}.tsx`.

- [ ] **Step 1: `GradeRing.tsx`** — SVG: anel + letra grande na cor da escala semântica; cinza tracejado quando `verdict==='inconclusive'` (mostra "—" + "não conclusivo").
- [ ] **Step 2: `FindingRow.tsx`** — pílula de severidade (cor), título, `description`, **evidência em mono** (sanitizada), `recommendation`. Referências como links discretos.
- [ ] **Step 3: `Honesty.tsx`** — callout para `inconclusive` ("Não conseguimos exercer o alvo — isto NÃO significa que está seguro") e para checks não-executados (cinza/tracejado).
- [ ] **Step 4: `ReportView.tsx`** — compõe: header (URL mono + data) + GradeRing + resumo por severidade + lista de FindingRow + Honesty + EmailCapture + ZapApiSupporter. Server component puro (recebe `PassiveScanResult`).
- [ ] **Step 5:** Commit `feat(web): componentes de relatório (grade ring, findings, honestidade)`.

---

## Task 6: Página de resultado `/r/[shareId]` (SSR compartilhável)

**Files:** criar `src/app/r/[shareId]/page.tsx`.

- [ ] **Step 1:** server component: `getStore().getByShareId(params.shareId)`; null → `notFound()`. Render `<ReportView result={...} />`. `generateMetadata`: OG dinâmica com a nota (`/api/badge/[shareId]` como imagem) para preview rico ao compartilhar.
- [ ] **Step 2:** Commit `feat(web): página de resultado compartilhável /r/[shareId]`.

---

## Task 7: Badge SVG dinâmico (`GET /api/badge/[shareId]`)

**Files:** criar `src/app/api/badge/[shareId]/route.ts`.

- [ ] **Step 1:** lê o resultado; gera um SVG (string) com a letra + cor da escala + "fracta.pro"; `Content-Type: image/svg+xml`, cache `public, max-age=3600`. `verdict inconclusive` → badge cinza "—". shareId inexistente → SVG neutro "?".
- [ ] **Step 2:** Commit `feat(web): badge SVG dinâmico da nota`.

---

## Task 8: ScanForm + Home + seções

**Files:** criar `src/components/{ScanForm,Pipeline,SampleReport,EmailCapture,ZapApiSupporter}.tsx`, `src/app/api/email/route.ts`, `src/app/page.tsx`.

- [ ] **Step 1: `ScanForm.tsx`** (`'use client'`): input controlado + submit → `fetch('/api/scan', POST)` → on success `router.push('/r/'+shareId)`; estados de loading/erro (mensagens honestas: recusa SSRF, rate-limit, inacessível). A11y: label, `aria-busy`, foco no erro.
- [ ] **Step 2: `SampleReport.tsx`** — relatório-amostra REAL estático (dados de um scan de verdade, sanitizado) pro herói. Inclui 1 check "não verificado".
- [ ] **Step 3: `Pipeline.tsx`**, `ZapApiSupporter.tsx`, `EmailCapture.tsx` (`'use client'`, POST `/api/email`), `api/email/route.ts` (valida e-mail, `store.saveEmail(email,'waitlist')`, rate-limit leve).
- [ ] **Step 4: `page.tsx`** — compõe as 6 seções do DNA. Server component; o `ScanForm`/`EmailCapture` são as ilhas client.
- [ ] **Step 5:** smoke local: home carrega, scan em `example.com` → redireciona pra `/r/...` com nota; e-mail capturado; zero erro de console. Commit `feat(web): home autoral + scan form + captura de e-mail`.

---

## Task 9: Build de produção + verificação local

- [ ] **Step 1:** `pnpm --filter @fracta/web build` (Next standalone) — confirmar sucesso, sem erro de bundling do motor (node:sqlite/dns ficam externos).
- [ ] **Step 2:** `pnpm build && pnpm test` no monorepo — sem regressão.
- [ ] **Step 3:** rodar o standalone localmente e exercer o fluxo e2e (scan real benigno + link compartilhável + badge). 
- [ ] **Step 4:** Commit `chore(web): build de produção verificado`.

---

## Self-review (feito ao escrever)
- **Cobertura da spec v1:** scan passivo (HEADERS+TLS-ish+cookies+LGPD-lite) ✅ via `@fracta/web-scan`; SSRF guard na API ✅(T4); rate-limit+cache ✅(T4); nota A–F ✅(T5); `/r/[shareId]` compartilhável ✅(T6); captura de e-mail ✅(T8); ZAP-API discreto ✅(T8); badge SEO ✅(T7); honestidade visual ✅(T5). Sem agentes intrusivos (não importados).
- **Segurança:** SSRF guard antes de qualquer fetch ✅; pré-requisito de redirect/rebinding sinalizado (T4) — bloqueia exposição pública até fechar.
- **Risco de placeholder:** componentes visuais descritos por responsabilidade (não código linha-a-linha) porque o executor é o próprio autor com o DNA acima como spec; os pontos NÃO-óbvios (SSRF/rate-limit/cache/store singleton/badge/config) têm código real.

## Próximo
- **Plano 3 (infra):** Dockerfile standalone, Actions→GHCR, VPS pull, nginx `fracta.pro`+Let's Encrypt, `default_server`→444, volume p/ o `fracta-web.db`, porta interna 3850.
