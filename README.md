# Fracta

> The complete SaaS audit framework — multi-agent security and docs scanner.

Fracta runs a fleet of specialized agents against a target SaaS (staging) and
produces a single report covering broken authentication, IDOR, missing security
headers, CORS misconfiguration, and stale documentation. Designed for solo
founders and small teams who can't afford a manual pentest every release.

**Status:** v0.1 alpha — interface stable enough to depend on, agent surface
will grow. Built and battle-tested across the author's own SaaS portfolio
(DoutorINSS, Veredicto, Tribux, IATech).

## Why Fracta

- **Multi-agent, not monolithic** — each concern (auth, IDOR, headers, docs) is
  a standalone agent with its own concurrency budget and timeout.
- **TypeScript end-to-end** — agents, orchestrator, CLI and MCP server share the
  same `Finding` shape. No JSON-by-convention.
- **MCP-native** — every scan tool is exposed through the
  [Model Context Protocol](https://modelcontextprotocol.io), so Claude Code (or
  any MCP client) can run scans on demand.
- **Stack-aware** — targets declare their stack (`nestjs`, `prisma`, `nextjs`,
  `stripe`, …) and agents tailor their tests accordingly.
- **OWASP-aligned** — findings link to OWASP API Security Top 10 and CWE
  references; reports group by severity (`critical → info`).

## Quickstart

```bash
# 1. Clone and install
git clone https://github.com/andersongadelhaadv-cmyk/fracta.git
cd fracta
pnpm install
pnpm build

# 2. Configure your target
cp configs/targets.yaml configs/targets.local.yaml
$EDITOR configs/targets.local.yaml   # point at *staging*, never prod

# 3. Run a scan
pnpm --filter @fracta/cli exec fracta scan \
  --config ./configs/targets.local.yaml \
  --target exemplo-saas \
  --depth full
```

Reports land in `./fracta-reports/<runId>.md` and `.json`.

> ⚠️ **Never run Fracta against production with real customer data.** It probes
> authentication, enumerates IDs, and hammers login endpoints to test rate
> limits. Use staging environments only.

## Architecture

```
┌──────────┐    ┌──────────────────────────────┐    ┌──────────────┐
│  CLI /   │───▶│       FractaOrchestrator     │───▶│  @fracta/    │
│  MCP     │    │  (concurrency, failOn, depth)│    │   reporter   │
└──────────┘    └──────────────┬───────────────┘    └──────────────┘
                               │ scope
                               ▼
                ┌──────────────────────────────┐
                │  Registered SecurityAgents   │
                ├──────────────────────────────┤
                │  • @fracta/agent-auth        │   broken auth, alg:none, brute force
                │  • @fracta/agent-headers     │   HSTS, CSP, CORS, X-Frame-Options
                │  • @fracta/agent-idor        │   BOLA, ID enumeration
                │  • @fracta/agent-docs        │   stale docs, legacy files, TODOs
                │  • @fracta/agent-tenant      │   multi-tenancy isolation (v0.2)
                │  • @fracta/agent-race        │   race conditions (v0.2)
                └──────────────────────────────┘
```

Every agent implements one interface (`SecurityAgent` in `@fracta/core`) and
returns a uniform `Finding[]`. The orchestrator runs them in chunks
(`concurrency` controls the chunk size), aggregates the findings, sorts by
severity, and decides `passed/failed` from the `failOn` list.

## Packages

| Package                   | Purpose                                         |
| ------------------------- | ----------------------------------------------- |
| `@fracta/core`            | Types, HTTP client, orchestrator                |
| `@fracta/agent-auth`      | Broken authentication, malformed JWTs, rate-limit |
| `@fracta/agent-headers`   | Security headers + CORS misconfiguration        |
| `@fracta/agent-idor`      | Object-level authorization + ID enumeration     |
| `@fracta/agent-docs`      | Markdown audit (stale, legacy, duplicate H1s)   |
| `@fracta/agent-tenant`    | Multi-tenancy isolation (stub, v0.2)            |
| `@fracta/agent-race`      | Race-condition abuse (stub, v0.2)               |
| `@fracta/reporter`        | Markdown + JSON report generators               |
| `@fracta/cli`             | `fracta` command-line entry point               |
| `@fracta/mcp-server`      | MCP server exposing every scan tool             |

## Configurando CI

The repo ships a GitHub Actions workflow at `.github/workflows/pentest.yml`
that runs Fracta on each push. It works out of the box with **no secrets**
(skipping live-target steps), and you can enable a full scan by setting these
repository secrets in **Settings → Secrets and variables → Actions**:

| Secret                | What it does                                                            |
| --------------------- | ----------------------------------------------------------------------- |
| `FRACTA_TARGET_URL`   | Base URL of the staging target to scan (e.g. `https://staging.app.com`) |
| `FRACTA_AUTH_EMAIL`   | Test-account email used by the AUTH/IDOR agents                         |
| `FRACTA_AUTH_PASSWORD`| Test-account password (use a throwaway staging account)                 |

If any of these are missing, the workflow falls back to **build + tests only**
and the live-scan step is skipped — CI stays green. Once you add them, the
nightly scan publishes a Markdown report as an artifact.

## Roadmap

- **v0.2** — flesh out `@fracta/agent-tenant` and `@fracta/agent-race`, add
  Stripe webhook replay agent, ship `CONTRIBUTING.md` + `SECURITY.md`.
- **v0.3** — skill packs (per-stack: NestJS, Prisma, Stripe, Supabase) and a
  GitHub App for inline PR comments.
- **v1.0** — stable plugin API, hosted SaaS edition for teams that want
  scheduled scans without running their own runners.

## License

[MIT](./LICENSE) © 2026 Anderson Gadelha
