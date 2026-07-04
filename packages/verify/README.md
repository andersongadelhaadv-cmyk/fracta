# @fracta/verify

Tier de **verificação em runtime** do Fracta. Carrega a página num Chromium headless (Playwright, lazy/opt-in) e CONFIRMA, com evidência, o que o scanner passivo só supõe: quais trackers e cookies disparam **antes de qualquer consentimento**, e se há um CMP real que os bloqueia.

## Uso

- MCP: tool `verify_consent { url }` (via `fractascan-mcp`).
- CLI: `fractascan verify <url>`.

Requer Chromium: `npx playwright install chromium`. Sem ele, degrada com uma mensagem acionável (nunca quebra).

## Honestidade / escopo

- **SSRF (limitação honesta):** há um pré-check do host inicial + um interceptor que bloqueia requisições diretas a IPs privados/internos + um guard que recusa (inconclusive) se a navegação aterrissar num host privado. PORÉM, um headless segue redirects do servidor internamente antes da interceptação, então **redirect/subrecurso apontando para hosts internos não é totalmente prevenido**. Use `verify` apenas em alvos que você controla/autoriza. (Fechar isso por completo é um follow-up rastreado.)
- v1 verifica apenas consentimento/trackers. Não substitui revisão jurídica.

## Caso âncora (e2e vivo, fora do CI)

`zap-api.tech` — o passive vê só "Google Analytics"; o verify enxerga o **Meta Pixel** (injetado por GTM) e confirma o disparo **pré-consentimento** (`_fbp`, `facebook.com/tr`).

MIT © Anderson Gadelha
