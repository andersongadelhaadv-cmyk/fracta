# Prompt premium — Home fracta.pro (rodar em sessão nova, contexto limpo)

> Cole o bloco abaixo numa sessão nova do Claude Code aberta em `c:\Users\ander_kxypaxu\Fracta`.

---

Você é o engenheiro-fundador do **Fracta**. Missão desta sessão: **construir a home do `fracta.pro` e colocá-la em PRODUÇÃO** — uma home **exclusiva, autoral, com cara de ferramenta de segurança de verdade**, NUNCA com cara de landing de IA genérica. Trabalhe ponta a ponta: design → build → deploy → verificação. Use as skills.

## 0. Ancore-se primeiro (não pule)
Antes de qualquer código, leia e internalize (são a fonte da verdade, já decididos):
- `MEMORY.md` e `memory/project_fracta_pro_produto.md` — decisões TRAVADAS do produto.
- `memory/project_refactor_robustez.md` — natureza do motor (detecção determinística, LLM opt-in).
- `docs/superpowers/specs/2026-06-29-fracta-pro-landing-scanner-design.md` — spec v1.
- `docs/superpowers/plans/2026-06-29-fracta-pro-scan-engine.md` — plano do motor `@fracta/web-scan`.
- `docs/qa/2026-06-29-dissect.md` — QA do motor atual (lições de honestidade: "ausência de achado nunca é seguro").
- `packages/agents/headers/src/index.ts` e `packages/core/src/{http-client,health}.ts` — o motor que você vai reusar.

Estado: monorepo pnpm+turbo (TS, ESM). Branch `feat/fracta-pro-landing`. `@fracta/web-scan` está só scaffoldado (Task 1). `apps/web` ainda não existe.

## 1. Constraints TRAVADAS (não relitigar)
- **Arquitetura:** novo `apps/web` (Next.js App Router + Tailwind) reusando os agentes Fracta como workspace deps — **mesmo motor**, zero reimplementação de detecção.
- **v1 = scanner web SÓ PASSIVO:** HEADERS + TLS/HTTPS + cookies + LGPD-lite (beta). Nota **A–F** compartilhável. **Captura de e-mail** (sinal de demanda). **Tudo grátis.**
- **PROIBIDO no web:** agentes intrusivos (AUTH/IDOR/RACE/STRIPE/TENANT) — são "atacar terceiros" + risco legal. Ficam CLI-only.
- **SSRF guard é NÃO-NEGOCIÁVEL** antes de expor a caixa de scan: bloquear IP interno/privado/loopback/link-local/metadata (169.254.169.254), resolver DNS e revalidar, só http/https, timeout curto. Sem guard → **não suba a caixa de scan** (use waitlist como CTA).
- **Rate-limit por IP** + **cache por URL** (mesmo padrão de `@fracta/store`, `node:sqlite`).
- **ZAP-API = apoiador discreto** (banner "ecossistema" sutil na página de resultado), **nunca** o CTA principal.
- **Honestidade como marca:** quando um check não roda, a UI diz "não verificado" — jamais finge verde. Espelha a regra do motor.

## 2. DNA visual — "exclusiva, não-IA-genérica" (use o skill `interface-design`)
O usuário REJEITA explicitamente cara de IA genérica. Mire numa identidade autoral de **ferramenta de segurança séria**, na linhagem de `securityheaders.com` / SSL Labs / Vercel, mas com personalidade própria:
- **Dark-first**, tipografia com **mono** para dados/evidência (a marca FRACTA já tem ASCII/terminal), **um** acento de cor próprio e disciplinado.
- **Dirigida à prova:** o herói NÃO é ilustração 3D fofa nem "Powered by AI ✨". É a **caixa de scan** + um **relatório real** renderizado (a nota A–F, headers achados, evidência sanitizada). O produto é a demonstração.
- **Anti-padrões PROIBIDOS:** gradiente roxo→rosa clichê, blobs/glassmorphism aleatório, emojis decorativos, "🚀 Supercharge your X with AI", three-column "Features" genérico, ilustrações undraw, copy vazia de marketing.
- **Cruze os eixos da marca:** segurança técnica + **LGPD** + **autoridade jurídica** (dono é advogado, frota legaltech) + honestidade. Copy em PT-BR, direta, técnica, confiante, sem hype.
- Cada elemento deve parecer **feito à mão para o Fracta** — se um trecho caberia em qualquer SaaS, reescreva.

## 3. Processo (skills, nesta ordem)
O brainstorming já foi feito (a spec existe) — **não refaça**. Vá para:
1. `superpowers:writing-plans` → escreva o **Plano 2 (`apps/web` + home)** e o **Plano 3 (infra/deploy)** como o memory descreve. Salve em `docs/superpowers/plans/`.
2. Implemente via `superpowers:subagent-driven-development` (1 implementador por tarefa; subagente revisor nas tarefas com lógica — SSRF guard, grader, rate-limit).
3. `superpowers:test-driven-development` para toda lógica (SSRF guard, grader A–F, parsing). RED→GREEN→REFACTOR, sem exceção.
4. `superpowers:requesting-code-review` antes de finalizar.

## 4. Escopo desta sessão (o que "pronto" significa)
**Shippable mínimo, em produção, fixando o vazamento:**
- [ ] `apps/web` Next.js com a **home autoral** (DNA acima) — herói = caixa de scan + relatório-amostra real.
- [ ] **Fluxo de scan passivo funcionando** end-to-end: input URL → SSRF guard → HEADERS (reusa o agente) + TLS + cookies → **nota A–F** → página de resultado **compartilhável** (shareId) → **captura de e-mail**.
  - Se o motor completo não fechar com segurança em uma sessão: suba a home + **waitlist** como CTA e marque o scan como "beta — entrando no ar", **sem** expor caixa sem SSRF guard.
- [ ] Acessibilidade básica (contraste, foco, semântica), responsivo, sem console errors.

## 5. Deploy em PRODUÇÃO (use o skill `padroniza-cicd`)
- Padrão da frota: **build no GitHub Actions → imagem no GHCR → VPS só faz pull + restart** (a VPS nunca builda). Dockerfile do `apps/web` (Next standalone).
- **nginx:** criar server block dedicado **`fracta.pro`** + cert **Let's Encrypt**, e **endurecer o `default_server` para retornar 444** — isso corrige a causa-raiz (hoje `fracta.pro` cai no default e serve a home do ADVOCUS com erro de CORS).
- VPS compartilhada `76.13.170.79` (`ssh hostinger`, apps em `/opt/apps`). **Nunca** buildar Docker na VPS; **nunca** tocar em outros apps além do necessário pro vhost.
- Variáveis/segredos via ambiente; nada de credencial commitada (o CI tem gitleaks — mantenha verde).

## 6. Verificação antes de declarar pronto (skills `qa-frota` + `verify`)
- Rode `qa-frota fracta full` contra a home **em produção** (read-only/smoke): home carrega, scan roda numa URL benigna (ex.: `https://example.com`), nota A–F aparece, link compartilhável funciona, e-mail é capturado, **nenhum** check finge verde.
- Confirme: `https://fracta.pro` serve a home do Fracta (não mais ADVOCUS), TLS válido, e o `default_server` agora responde 444 a host desconhecido.
- Só então finalize com `superpowers:finishing-a-development-branch` (PR para `master`).

## 7. Princípios inegociáveis
- **Honestidade > cobertura:** UI nunca afirma o que não mediu. (Mesma lei do motor — ver o QA report.)
- **Default-safe:** destrutivo só em local; produção só read-only/smoke. SSRF guard antes de qualquer scan público.
- **Mostre, não conte:** o relatório real é o melhor marketing. Menos copy, mais prova.
- **Pare e me pergunte** apenas se uma decisão for irreversível e não estiver coberta pela spec/memory; o resto, decida pelo mais inteligente e siga.

Comece lendo os arquivos da seção 0 e me diga o plano (seções 1–6) antes de escrever código de produção.
