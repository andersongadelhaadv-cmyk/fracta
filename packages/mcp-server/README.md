# @fracta/mcp-server

Servidor **MCP** (Model Context Protocol) do [Fracta](https://github.com/andersongadelhaadv-cmyk/fracta) — expõe o scanner de segurança + LGPD como ferramentas para o Claude Code, Cursor ou qualquer cliente MCP.

## Config (1 linha)

```json
{
  "mcpServers": {
    "fracta": { "command": "npx", "args": ["-y", "@fracta/mcp-server"] }
  }
}
```

Requer Node 20+.

## Ferramentas

- **`passive_scan <url>`** — scan passivo de qualquer URL, zero setup (headers, TLS, cookies, **LGPD** — lê a política, **DNS/e-mail**, **CSP**). Nota A–F.
- **`scan_repo [path]`** — auditoria SAST do repositório local (deps, secrets, stack, **LGPD/inventário/ROPA**, docs). "Audite o código que estou escrevendo, agora."
- **`scan_target`** / `test_auth` / `test_idor` / `check_headers` — scan completo/escopado de um alvo do `targets.yaml`.
- **`get_findings`** / `generate_report` — findings e relatório do último scan.

Detecção 100% determinística; borda LLM opt-in (zero token por padrão).

MIT © Anderson Gadelha
