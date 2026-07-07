# Fracta

> The complete SaaS audit framework — multi-agent security and docs scanner.

Fracta runs a fleet of specialized agents against a target SaaS — its live
staging surface (DAST) **and** its repository (SAST/posture) — and produces a
single report covering broken authentication, IDOR, missing security headers,
CORS misconfiguration, vulnerable dependencies, leaked secrets, insecure
infrastructure, LGPD compliance gaps, and stale documentation. Designed for solo
founders and small teams who can't afford a manual pentest every release.

**Status:** v0.4 — twelve agents (DAST + repository-based) across the full audit
surface, cross-run regression/suppression state, target health preflight, and an
optional LLM edge for prioritization and gated fix drafting. Interface stable
enough to depend on; agent surface keeps growing. Battle-tested across the
author's own SaaS portfolio (DoutorINSS, Veredicto, Tribux, IATech).

## Why Fracta

- **Robust by contract, not by doing more** — every check is isolated: an agent
  that throws becomes a declared `status: error`, never taking the run down;
  missing input becomes a declared `skipped` ("not verified" ≠ "safe"). The
  report always states what *didn't* run.
- **Multi-agent, not monolithic** — each concern (auth, IDOR, headers, deps,
  secrets, infra, compliance, …) is a standalone agent with its own concurrency
  budget and timeout, run inside `runCheckIsolated()`.
- **One SaaS per run** — `scan` requires `--target`. The blast radius is one
  system at a time, by design.
- **Detect ≠ fix, read-only by default** — repository agents are thin wrappers
  over trusted tools (`npm audit`, `gitleaks`) and never write. Fixes are only
  ever *proposed* (`proposedFix` with an honest `riskOfApplying`) — never applied.
- **Deterministic, stateful findings** — each finding has a stable id
  (`sha256(saas|layer|rule|location)`), so re-running the same SaaS detects
  **regressions** (a resolved issue that came back) and honors **suppressions**
  (reviewed false-positives leave the top of the report without vanishing from
  history). Backed by a lightweight `node:sqlite` store.
- **LLM only at the edge** — detection is 100% deterministic. The optional LLM
  pass only *prioritizes* findings and *drafts* gated fixes; it never decides a
  vulnerability, changes a severity, applies a fix, or touches the target.
- **Measured, not just claimed** — accuracy is benchmarked, not asserted. On a
  24-case corpus labeled from external ground truth (CSP spec / OWASP / MDN),
  the passive CSP + cookie checks score **100% precision / 80% recall** — and the
  recall shortfall is fully explained by two *documented* gaps we don't cover yet
  (`frame-ancestors`, `form-action`). An honest number shows the limits; it doesn't
  hide them. See [`packages/web-scan/BENCHMARK.md`](packages/web-scan/BENCHMARK.md)
  (reproducible; runs in CI as a regression guard).
  Disable it (`--no-llm` / no API key) and detection is unchanged.
- **TypeScript end-to-end** — agents, orchestrator, CLI and MCP server share the
  same `Finding` / `AuditReport` shape. No JSON-by-convention.
- **MCP-native** — every scan tool is exposed through the
  [Model Context Protocol](https://modelcontextprotocol.io), so Claude Code (or
  any MCP client) can run scans on demand.
- **Stack-aware** — targets declare their stack (`nestjs`, `prisma`, `nextjs`,
  `stripe`, `supabase`, …) and skill packs run dedicated probes (Swagger
  exposure, Prisma error leaks, Supabase REST/Storage misconfig) only on the
  matching stack.
- **OWASP-aligned** — findings link to OWASP API Security Top 10 and CWE
  references; reports group by severity (`critical → info`).

## Quickstart

### CLI — `npx`, sem clonar (Node 20+)

```bash
# scan de um alvo declarado no targets.yaml (aponte para STAGING, nunca prod)
npx fractascan scan --config ./targets.yaml --target meu-saas --depth full

# ou instale global e use `fracta`:
npm i -g fractascan
fracta scan --config ./targets.yaml --target meu-saas
```

O `targets.yaml` declara o alvo (url de staging, `stack`, `repoPath` opcional para o SAST). Modelo em [`configs/targets.yaml`](configs/targets.yaml).

> Só quer o **scan passivo de uma URL pública** (headers/TLS/cookies/LGPD/DNS/CSP), sem setup? Use **[fracta.pro](https://fracta.pro)** ou o MCP abaixo.

### MCP — Claude Code / Cursor (config de 1 linha)

```json
{
  "mcpServers": {
    "fracta": { "command": "npx", "args": ["-y", "fractascan-mcp"] }
  }
}
```

Aí peça no editor:
- *"scaneie https://exemplo.com"* → `passive_scan` (qualquer URL, zero setup)
- *"audite este repositório"* → `scan_repo` (SAST do projeto atual: deps, secrets, stack, **LGPD/inventário**, docs)
- scan completo de um target do `targets.yaml` → `scan_target`

### A partir do código (contribuir)

```bash
git clone https://github.com/andersongadelhaadv-cmyk/fracta.git && cd fracta
pnpm install && pnpm build
cp configs/targets.yaml configs/targets.local.yaml   # aponte para staging
pnpm --filter fractascan exec fracta scan --config ./configs/targets.local.yaml --target exemplo-saas --depth full
```

Reports land in `./fracta-reports/<slug>-<timestamp>.md` and `.json` — identical
in content (the JSON is the persisted `AuditReport` that feeds a future panel).

### Scan flags

| Flag           | Default               | What it does                                              |
| -------------- | --------------------- | -------------------------------------------------------- |
| `-t, --target` | *(required)*          | Target name from `targets.yaml`. One SaaS per run.       |
| `-c, --config` | `./configs/targets.yaml` | Path to the targets file.                             |
| `-d, --depth`  | `full`                | `quick` \| `full` \| `paranoid`.                         |
| `-o, --output` | `./fracta-reports`    | Report output directory.                                 |
| `--state`      | `./fracta-state.db`   | SQLite file holding cross-run regression/suppression state. |
| `--no-state`   | off                   | Disable cross-run state (no regression/suppression).     |
| `--no-llm`     | off                   | Disable the LLM edge (prioritization + fix drafting).    |
| `--fail-on`    | `critical,high`       | Severities that cause `exit(1)`.                         |
| `--docs-path`  | `./`                  | Repository path for the docs audit.                      |
| `-v, --verbose`| off                   | Verbose output.                                          |

The LLM edge activates only when `ANTHROPIC_API_KEY` is set **and** `--no-llm`
was not passed (model overridable via `FRACTA_LLM_MODEL`, default
`claude-opus-4-8`). Repository-based agents activate per target by the optional
`repoPath`, `infra`, and `frontend` fields in `targets.yaml`; absent input means
those checks are reported as `skipped`, never as "safe".

> ⚠️ **Never run Fracta against production with real customer data.** It probes
> authentication, enumerates IDs, and hammers login endpoints to test rate
> limits. Use staging environments only.

## Architecture

```
┌──────────┐   ┌─────────────────────────────────┐   ┌──────────────┐
│  CLI /   │──▶│        FractaOrchestrator       │──▶│  @fracta/    │
│  MCP     │   │  preflight health → isolated    │   │   reporter   │
└──────────┘   │  checks → AuditReport           │   └──────────────┘
               └───┬─────────────────────┬───────┘
        @fracta/store │ status/regression │ scope        @fracta/llm
     (node:sqlite,    ▼                   ▼          (edge: prioritize +
      cross-run)  ┌───────────────────────────────┐   draft gated fixes,
                  │  Registered SecurityAgents    │   optional, never
                  ├───────────────────────────────┤   touches detection)
       DAST (url) │  • agent-auth     │ broken auth, alg:none, brute force
                  │  • agent-headers  │ HSTS, CSP, CORS, X-Frame-Options
                  │  • agent-idor     │ BOLA, ID enumeration
                  │  • agent-tenant   │ multi-tenancy isolation, admin routes
                  │  • agent-race     │ race conditions, login timing
                  │  • agent-stripe   │ webhook signature, replay, unsigned POST
        repo/SAST │  • agent-dependencies │ npm audit (read-only)
        (repoPath)│  • agent-secrets  │ gitleaks history, sanitized
                  │  • agent-stack    │ deterministic SAST + frontend checks
                  │  • agent-infra    │ read-only SSH/Docker/port posture
                  │  • agent-compliance │ LGPD sensitive-data heuristics
                  │  • agent-docs     │ stale docs, legacy files, TODOs
        skills    │  • skill-nestjs   │ Swagger exposure, health leaks
                  │  • skill-prisma   │ Studio exposure, P-code error leakage
                  │  • skill-supabase │ REST enumeration, public Storage buckets
                  └───────────────────────────────┘
```

Every agent implements one interface (`SecurityAgent` in `@fracta/core`) and
returns a uniform `Finding[]`. The orchestrator first runs a **target health
preflight** (repo reachable? staging responding? VPS reachable?) — aborting only
when a mandatory `repoPath` is inaccessible, and marking dependent checks
`skipped` otherwise. It then runs each agent inside `runCheckIsolated()` (timeout
+ try/catch → a `CheckResult` of `ok | error | skipped`), so one failing check
never derails the others. The `@fracta/store` layer applies cross-run status
(open / regression / suppressed) before the report is assembled, sorted by
severity, and graded `passed/failed` from the `failOn` list.

## Packages

| Package                     | Purpose                                         |
| --------------------------- | ----------------------------------------------- |
| `@fracta/core`              | Types, contract, HTTP client, orchestrator, health preflight |
| `@fracta/store`             | `node:sqlite` finding history — regression & suppression between runs |
| `@fracta/llm`               | LLM edge — prioritizes findings + drafts gated fixes (optional) |
| `@fracta/agent-auth`        | Broken authentication, malformed JWTs, rate-limit |
| `@fracta/agent-headers`     | Security headers + CORS misconfiguration        |
| `@fracta/agent-idor`        | Object-level authorization + ID enumeration     |
| `@fracta/agent-tenant`      | Multi-tenancy isolation, admin route exposure, header injection |
| `@fracta/agent-race`        | Race-condition abuse, login timing attacks      |
| `@fracta/agent-stripe`      | Stripe webhook: signature, replay window, unsigned POST acceptance |
| `@fracta/agent-dependencies`| `npm audit` wrapper (deterministic, read-only)  |
| `@fracta/agent-secrets`     | `gitleaks` history scan — sanitized (type + location, never the value) |
| `@fracta/agent-stack`       | Deterministic SAST for NestJS/Next/Prisma + frontend checks |
| `@fracta/agent-infra`       | Read-only VPS/Docker/SSH posture (never executes anything) |
| `@fracta/agent-compliance`  | LGPD heuristics for sensitive-data exposure     |
| `@fracta/agent-docs`        | Markdown audit (stale, legacy, duplicate H1s)   |
| `@fracta/skill-nestjs`      | NestJS-only: Swagger/OpenAPI exposure, health endpoint leaks    |
| `@fracta/skill-prisma`      | Prisma-only: Studio exposure, P-code/stack-trace error leakage  |
| `@fracta/skill-supabase`    | Supabase-only: REST table enumeration, public Storage buckets   |
| `@fracta/reporter`          | Consolidated Markdown + JSON report (JSON ≡ MD) |
| `fractascan` (npm)          | `fracta` command-line entry point               |
| `fractascan-mcp` (npm)      | MCP server exposing every scan tool             |

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

- **v0.2** — `@fracta/agent-tenant`, `@fracta/agent-race` and `@fracta/agent-stripe`
  shipped. Set `STRIPE_WEBHOOK_SECRET` to also test replay-window tolerance.
- **v0.3** — skill packs `@fracta/skill-nestjs`, `@fracta/skill-prisma` and
  `@fracta/skill-supabase` shipped (auto-activated by `target.stack`).
- **v0.4** — robustness contract shipped: isolated checks
  (`ok | error | skipped`), deterministic finding ids, target health preflight,
  cross-run regression/suppression (`@fracta/store`), five repository-based
  agents (dependencies, secrets, stack, infra, compliance), the optional LLM
  edge (`@fracta/llm`), and the consolidated JSON ≡ Markdown report.
- **v0.5** — GitHub App for inline PR comments and per-finding remediation hints.
- **v1.0** — stable plugin API, hosted SaaS edition for teams that want
  scheduled scans without running their own runners.

## License

[MIT](./LICENSE) © 2026 Anderson Gadelha
