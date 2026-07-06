/** Cache de resultado por URL (rescan recente é servido do cache). */
export const CACHE_TTL_MS = 60 * 60 * 1000 // 1h

/** Rate-limit por IP (anti-abuso/recon). Conservador no v1. */
export const RATE_LIMIT = { limit: 10, windowMs: 10 * 60 * 1000 } // 10 análises / 10 min

/** Caminho do SQLite (volume na VPS). */
export const DB_PATH = process.env.FRACTA_WEB_DB ?? './fracta-web.db'

export const REPO_URL = 'https://github.com/andersongadelhaadv-cmyk/fracta'
export const ZAP_API_URL = 'https://zap-api.tech'
export const PREVIUSIA_URL = 'https://previusia.com.br'

// ── Distribuição MCP + CLI (npm). Fonte ÚNICA reusada pela home, /mcp e CTA. ──

/** Instala o MCP no Claude Code num comando (macOS/Linux). */
export const MCP_INSTALL_CMD = 'claude mcp add fracta -- npx -y fractascan-mcp'

/** Windows: `npx` não é spawnável direto pelo cliente MCP (é `npx.cmd`) → envolve em `cmd /c`. */
export const MCP_INSTALL_CMD_WIN = 'claude mcp add fracta -- cmd /c npx -y fractascan-mcp'

/** Config MCP p/ clientes que editam JSON (Claude Desktop, Cursor, etc.) — macOS/Linux. */
export const MCP_JSON_CONFIG = `{
  "mcpServers": {
    "fracta": { "command": "npx", "args": ["-y", "fractascan-mcp"] }
  }
}`

/** Config MCP no Windows (o cliente spawna sem shell → `npx` direto dá ENOENT). */
export const MCP_JSON_CONFIG_WIN = `{
  "mcpServers": {
    "fracta": { "command": "cmd", "args": ["/c", "npx", "-y", "fractascan-mcp"] }
  }
}`

export interface McpTool {
  name: string
  /** Linguagem simples, sem jargão — pensado p/ dev iniciante. */
  desc: string
  /** 'zero' = funciona sem config; 'targets' = precisa do targets.yaml. */
  group: 'zero' | 'targets'
  /** true = ativo/intrusivo → só em sites que você controla. */
  intrusive: boolean
}

/** As 10 tools do fractascan-mcp (nomes conferidos no packages/mcp-server). */
export const MCP_TOOLS: McpTool[] = [
  { name: 'passive_scan', group: 'zero', intrusive: false, desc: 'Analisa qualquer URL (headers, TLS, cookies, LGPD-lite) e devolve nota A–F. Só GETs passivos — seguro em qualquer site.' },
  { name: 'scan_repo', group: 'zero', intrusive: false, desc: 'Auditoria do seu repositório local (dependências, secrets, código ciente do stack, LGPD/docs). Read-only — ótimo pra rodar na IDE enquanto você programa.' },
  { name: 'verify_consent', group: 'zero', intrusive: false, desc: 'Abre a página num browser real e confirma quais trackers/cookies disparam ANTES do consentimento — a prova de LGPD que o scan passivo só supõe.' },
  { name: 'audit_docs', group: 'zero', intrusive: false, desc: 'Audita os arquivos .md do repositório (README, docs) em busca de problemas.' },
  { name: 'scan_target', group: 'targets', intrusive: true, desc: 'Scan de segurança COMPLETO (todos os agentes) de um alvo declarado no seu targets.yaml.' },
  { name: 'test_auth', group: 'targets', intrusive: true, desc: 'Testa autenticação: JWT alg:none, brute force, tokens malformados.' },
  { name: 'test_idor', group: 'targets', intrusive: true, desc: 'Testa IDOR e acesso cruzado entre IDs/tenants.' },
  { name: 'check_headers', group: 'targets', intrusive: false, desc: 'Confere security headers e CORS de um alvo do targets.yaml.' },
  { name: 'get_findings', group: 'targets', intrusive: false, desc: 'Lista os achados do último scan, filtrados por severidade.' },
  { name: 'generate_report', group: 'targets', intrusive: false, desc: 'Gera o relatório do último scan em markdown ou JSON.' },
]
