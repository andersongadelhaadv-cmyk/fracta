# Fracta.pro — Landing + Scanner Web Passivo (v1) — Design

**Data:** 2026-06-29
**Status:** Aprovado no brainstorming; aguardando review do spec antes do plano de implementação.

## 1. Contexto e problema

O domínio `fracta.pro` aponta pra VPS, mas **não há server block nginx pra ele** → a requisição cai no `default_server` (que hoje serve o ADVOCUS). Resultado: `fracta.pro` exibe a home do ADVOCUS (com erros de CORS). Causa-raiz: default vhost não-neutro.

O Fracta hoje é uma ferramenta **OSS CLI + MCP** de auditoria de segurança de SaaS (12 agentes; detecção 100% determinística; LLM opt-in). Ainda **não tem home própria**.

## 2. Decisão comercial (travada)

- **Tudo grátis por enquanto.** A detecção é determinística → custo marginal é **só CPU** (sem sangria de LLM). Free generoso é sustentável.
- **Monetização adiada** (YAGNI): pensar em upsell quando houver tráfego. Capturar **sinal de demanda** desde já (email opcional) pra decidir informado depois.
- **Objetivo primário:** TRÁFEGO. Formato self-serve "teste de graça na hora" é o de maior tráfego/SEO da categoria (ref.: securityheaders.com, SSL Labs).
- **ZAP-API** (produto de dev: ponte WhatsApp↔SaaS) entra como **apoiador discreto** (banner intermitente / "ecossistema") na página de resultado — público dev se sobrepõe. Expectativa honesta: conversão scan→ZAP é dígito único baixo; o valor é volume + marca, não conversão alta. **Não** é o CTA principal.

## 3. Público e posicionamento

- **Público:** dev / founder técnico construindo SaaS (mesmo público do ZAP-API).
- **Diferencial (anti "scanner genérico"):** cruzar **segurança técnica + LGPD** com **autoridade jurídica real** (o dono é advogado, com frota de legaltech). E **honestidade como marca**: "diz quando NÃO sabe" (skip honesto, veredito inconclusivo) — mesmo DNA do LEXIA ("IA que cita fonte, nunca inventa").

## 4. Escopo do v1

### Faz
- **Scanner web self-serve PASSIVO**: visitante digita uma URL e recebe um relatório na hora.
- Checks **100% passivos** (apenas GETs, zero intrusão): **security headers** (HEADERS agent já existente), **TLS/HTTPS-enforce**, **flags de cookie** (`Secure/HttpOnly/SameSite`), e um bloco **"LGPD-lite" heurístico** (rotulado beta).
- **Nota A–F** + resumo (estilo securityheaders) — motor de SEO/compartilhamento.
- **Página de resultado compartilhável** (URL única por scan).
- **Captura de email opcional** ("quero monitoramento contínuo quando lançar").
- **Slot "Apoiado por ZAP-API"** discreto.
- **Home** institucional dirigida a prova (números reais da frota auditada) com o input de scan acima da dobra.

### NÃO faz (YAGNI / segurança)
- **Sem agentes intrusivos no web** (AUTH/IDOR/RACE/STRIPE/TENANT). Rodar isso contra URL arbitrária = ferramenta de atacar terceiros (risco legal + VPS vira origem de ataque). Esses ficam **CLI-only / gated por prova de propriedade**.
- Sem login, sem billing, sem dashboard, sem LGPD-deep.

## 5. Arquitetura

**Abordagem escolhida (1 de 3):** `apps/web` (Next.js App Router + TS) **dentro do monorepo Fracta**, importando os agentes como workspace deps. O scanner web **literalmente roda o motor do Fracta** (mesma engine, sempre em sincronia). Um pipeline de deploy só. Padrão da frota (Next.js → GHCR → VPS).

- Alternativas descartadas: (2) repo separado com Fracta como dep — pacotes não publicados no npm, atrito + risco de divergir; (3) shell-out pro CLI — frágil, sem type-safety, difícil controlar SSRF/subset.

**Infra/deploy:** Dockerfile no `apps/web` → build no GitHub Actions → imagem no GHCR → VPS faz pull (padrão `padroniza-cicd`). **nginx:** novo server block pra `fracta.pro` (+ `www`) com cert Let's Encrypt, proxy pro container; **endurecer o `default_server`** pra retornar **444** em host não reconhecido (corrige o vazamento do ADVOCUS e qualquer domínio solto futuro).

## 6. Componentes (cada um com um propósito)

- **`SsrfGuard`** — valida a URL antes de QUALQUER fetch: aceita só `http(s)`; resolve o hostname e **rejeita** loopback (`127/8`, `::1`), privado (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`, inclui metadata `169.254.169.254`), reservado, e (opção) portas não-padrão. Entrada: URL string. Saída: URL normalizada validada ou erro tipado. **Obrigatório** — um scanner de segurança vulnerável a SSRF é vexame e risco.
- **`PassiveScanner`** — orquestra só checks passivos. Reusa `@fracta/agent-headers`; adiciona `TlsCheck` (HTTPS forçado? redirect http→https?) e `CookieCheck` (flags do `Set-Cookie`) + `LgpdLiteCheck` (heurística: link de política de privacidade / banner de cookie — best-effort, rotulado beta). Entrada: URL validada. Saída: lista de findings (contrato `Finding` do core).
- **`Grader`** — findings → nota A–F + resumo curto. Determinístico.
- **`ScanStore`** — SQLite (`node:sqlite`, mesmo padrão do `@fracta/store`): tabela de resultados por **share-id**; **cache por URL** (rescan recente → cacheado, TTL configurável); tabela de **emails** capturados. Falha de persistência nunca derruba o scan (degradação graciosa, regra do core).
- **`RateLimiter`** — por IP (janela deslizante; backend SQLite ou memória). Anti-abuso/anti-proxy de recon.
- **Páginas (Next.js):** `Home` (hero + input de scan), `/r/[shareId]` (resultado SSR compartilhável), componente `ZapApiSupporter` (slot discreto), `EmailCapture`.

## 7. Fluxo de dados

```
URL digitada
  → SsrfGuard (rejeita interno/privado/metadata)
  → RateLimiter (por IP) + cache (por URL)
  → PassiveScanner (HEADERS + TLS + cookies + LGPD-lite)
  → Grader (nota A–F)
  → ScanStore (persiste, gera shareId)
  → render /r/[shareId] (nota + achados + EmailCapture + ZapApiSupporter)
```

## 8. Tratamento de erro (honestidade como marca)

- URL inválida → 400 com mensagem clara.
- SSRF bloqueado → recusa explícita ("não escaneamos endereços internos/privados").
- Rate-limited → 429 com orientação.
- Alvo inacessível / timeout → veredito **inconclusivo** (NUNCA "está seguro" falso — mesma regra do core).
- Falha parcial de um check → o check aparece como não-executado; ausência de achado ≠ seguro.

## 9. Testes

- **Unit:** `SsrfGuard` (IP privado/loopback/link-local/metadata, hostnames que resolvem p/ interno, esquemas inválidos), `Grader` (mapeamento findings→nota), `RateLimiter` (janela/limite), `CookieCheck`/`TlsCheck`.
- **Integração:** endpoint de scan contra um alvo de teste local (fixture), incluindo caminho SSRF-bloqueado e cache-hit.
- Reaproveita os testes já existentes dos agentes. CI roda Node 22 + gitleaks (já configurado).

## 10. Direção de design (skill `interface-design` no build)

Dark sóbrio coerente com a família ADVOCUS/LEXIA, com **acento próprio** pro Fracta (não clonar). Tokens de design via interface-design (hierarquia, espaçamento, profundidade — sem cara de template). Hero **dirigido a prova** (números reais da frota; input de scan acima da dobra). Visual do produto = **relatório real sanitizado**, não ilustração stock. Tom honesto ("diz quando não sabe"). LGPD/Brasil em destaque. Nota/grade compartilhável com badge (SEO/viralização).

## 11. Riscos e mitigações

- **SSRF** (principal) → `SsrfGuard` obrigatório, testado, antes de qualquer fetch.
- **Abuso (proxy de recon/DDoS)** → rate-limit por IP + cache + só passivo.
- **Vazamento de domínio (default vhost)** → endurecer `default_server` (444).
- **Custo** → passivo = CPU + banda baixos; LLM permanece off (opt-in).

## 12. Questões em aberto (resolver no plano)

- TTL do cache de scan e janela/limite exato do rate-limit (valores iniciais conservadores).
- Porta interna do container web na VPS (alocar fora das faixas em uso — ver [[infra-vps-deploy]]).
- Badge compartilhável: imagem estática gerada server-side ou SVG dinâmico (decidir no plano).
- LGPD-lite: conjunto exato de heurísticas do v1 (manter mínimo e honesto).
