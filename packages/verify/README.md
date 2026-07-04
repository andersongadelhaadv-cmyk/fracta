# @fracta/verify

Tier de **verificação em runtime** do Fracta. Carrega a página num Chromium headless (Playwright, lazy/opt-in) e CONFIRMA, com evidência, o que o scanner passivo só supõe: quais trackers e cookies disparam **antes de qualquer consentimento**, e se há um CMP real que os bloqueia.

## Uso

- MCP: tool `verify_consent { url }` (via `fractascan-mcp`).
- CLI: `fractascan verify <url>`.

Requer Chromium: `npx playwright install chromium`. Sem ele, degrada com uma mensagem acionável (nunca quebra).

## Honestidade / escopo

- Não executa validação SSRF por-conexão como o passive (um browser não permite): há um pré-check de host, mas **use em alvos que você controla/autoriza**.
- v1 verifica apenas consentimento/trackers. Não substitui revisão jurídica.

## Caso âncora (e2e vivo, fora do CI)

`zap-api.tech` — o passive vê só "Google Analytics"; o verify enxerga o **Meta Pixel** (injetado por GTM) e confirma o disparo **pré-consentimento** (`_fbp`, `facebook.com/tr`).

MIT © Anderson Gadelha
