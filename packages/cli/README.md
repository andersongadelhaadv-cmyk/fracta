# fractascan

Auditor de segurança + LGPD multi-agente para SaaS — **determinístico** (regra, não IA). Roda contra o staging (DAST: auth, IDOR, headers, CORS, race, Stripe…) **e** o repositório (SAST: dependências, secrets, stack, **LGPD/inventário**, docs) e gera um relatório A–F com **fixes copiáveis**.

## Uso

```bash
# scan de um alvo do targets.yaml (aponte para STAGING, nunca prod)
npx fractascan scan --config ./targets.yaml --target meu-saas --depth full

# global:
npm i -g fractascan && fracta scan --config ./targets.yaml --target meu-saas
```

Requer Node 20+. Modelo de `targets.yaml` e docs completos no repositório.

- **Scan passivo de uma URL, zero setup:** https://fracta.pro
- **MCP (Claude Code/Cursor):** `fractascan-mcp`
- **Repositório / docs:** https://github.com/andersongadelhaadv-cmyk/fracta

> ⚠️ Nunca rode contra produção com dados reais — os agentes intrusivos testam auth e enumeram IDs. Use staging.

MIT © Anderson Gadelha
