# @fracta/verify

Tier de **verificação em runtime** do Fracta. Carrega a página num Chromium headless (Playwright, lazy/opt-in) e CONFIRMA, com evidência, o que o scanner passivo só supõe: quais trackers e cookies disparam **antes de qualquer consentimento**, e se há um CMP real que os bloqueia.

## Uso

- MCP: tool `verify_consent { url }` (via `fractascan-mcp`).
- CLI: `fractascan verify <url>`.

Requer um Chromium: o Fracta usa o `playwright-core` (instalado como dependência opcional) e tenta, nesta ordem, um browser baixado (`npx playwright install chromium`) e o **Google Chrome do sistema**. Sem nenhum dos dois, degrada com uma mensagem acionável (nunca quebra).

## Honestidade / escopo

- **SSRF:** defesa em camadas — pré-check do host inicial + interceptor por-request que bloqueia IPs privados/internos + **validação por-hop de redirects** (cada `Location` de um 3xx é re-validado ANTES do browser emitir o próximo request, via `route.fetch({maxRedirects:0})` + `fulfill`) + guard pós-navegação que recusa (inconclusive) se ainda assim aterrissar num host privado. O vetor que a v1 documentava como aberto — um host público que faz `302 → 169.254.169.254` — está **fechado e provado server-side** por um teste de integração com Chromium real que confirma que o alvo interno **nunca recebe** o request (`verifier.redirect-ssrf.browser.test.ts`). Ainda assim, prefira `verify` em alvos que você controla/autoriza.
- v1 verifica apenas consentimento/trackers. Não substitui revisão jurídica.

## Caso âncora (e2e vivo, fora do CI)

`zap-api.tech` — o passive vê só "Google Analytics"; o verify enxerga o **Meta Pixel** (injetado por GTM) e confirma o disparo **pré-consentimento** (`_fbp`, `facebook.com/tr`).

MIT © Anderson Gadelha
