# REFACTOR_PLAN.md — Fracta → Robustez

> Plano curto e ordenado. Registra **o que muda e em que ordem**, respeitando as 6 regras
> inegociáveis do guia. Execução é incremental: um agente por vez, validável isoladamente.
> **Nada grande sem antes estar aqui.**

## 0. Reconciliação de premissas (LER PRIMEIRO)

O guia assume **NestJS 10 + Prisma 5 + PostgreSQL 16** e agentes SAST baseados em `repoPath`.
**A realidade do repo é outra** e isso foi confirmado com o usuário:

| Premissa do guia | Realidade do Fracta |
|---|---|
| NestJS + Prisma + Postgres | Monorepo **pnpm + turbo** de pacotes TS — **CLI + MCP stdio**, sem servidor, sem DB ("no port") |
| Alvo = `repoPath` (SAST) | Alvo = `url` (DAST sobre HTTP via `FractaHttpClient`) |
| Agentes: Dependencies, Secrets, Application, Stack, Infra, Compliance | Agentes: auth, docs, headers, idor, race, stripe, tenant + skills (nestjs/prisma/supabase) |
| `Finding.id` = hash determinístico | `Finding.id` = `randomUUID()` |
| `CheckResult` ok/error/skipped | inexistente (agente que falha some no `console.error`) |
| Estado entre runs (Prisma) | inexistente |
| LLM na borda | inexistente |
| Saída JSON + Markdown | ✅ já existe (`packages/reporter`) |

**Decisão (confirmada com o usuário):**
1. **Endurecer o que existe** (monorepo TS + agentes DAST) e **adotar o contrato de robustez** do guia —
   IDs determinísticos, `CheckResult` ok/error/skipped, `TargetHealth`, isolamento real,
   regressão/supressão, correção *gated*, LLM na borda.
2. **Adicionar os agentes baseados em repositório que faltam** (Dependencies via `npm audit`,
   Secrets via `gitleaks`, Stack-SAST, Infra read-only) **ao lado** dos agentes DAST atuais.
3. **Persistência leve em SQLite** (não Postgres/Prisma) — casa com o design "no port" CLI/MCP.

**Decisão de nomenclatura (anti-fragilidade):** mantemos os nomes de campo **em inglês** já usados
(`agent`, `severity`, `description`, `recommendation`, `evidence`) e **acrescentamos** apenas os campos
que carregam robustez (`camada`, `status`, id determinístico, `proposedFix.riskOfApplying`). Renomear
tudo para PT-BR seria churn que quebra 7 agentes + reporter + testes sem ganho de robustez — viola o
princípio "robustez não vem de fazer mais". (Rename cosmético, se desejado, é tarefa trivial no fim.)

---

## 1. Mapa de arquivos (o que cada pacote vira)

```
packages/core/src/
  types.ts           ← +CheckResult, +TargetHealth, +AuditReport, +ProposedFix, +SkippedCheck
                       Finding += camada,status ; Target += repoPath,infra,frontend,config
                       +stableFindingId() ; makeFinding() passa a aceitar {camada,rule,location}
  orchestrator.ts    ← runCheckIsolated() por agente → CheckResult (try/catch + timeout + duração)
                       +preflight TargetHealth ; monta AuditReport ; aplica status via store
  health.ts          ← NOVO: TargetHealthCheck (repo git? staging responde? vps alcançável?)
packages/store/      ← NOVO pacote: SQLite (better-sqlite3) — FindingHistory + AuditRun
                       applyStatus(findings): marca open/regression/suppressed e conta regressões
packages/reporter/   ← consome AuditReport (checks, target_health, resumo c/ erros/pulados/regressões)
packages/llm/        ← NOVO pacote (último, opcional): prioriza + redige proposedFix (Anthropic SDK)
packages/agents/
  dependencies/      ← NOVO: wrapper npm audit --json (repoPath)
  secrets/           ← NOVO: wrapper gitleaks (repoPath, histórico) — SANITIZA o segredo
  stack/             ← NOVO: SAST grep determinístico (helmet, $queryRaw concat, ValidationPipe,
                       throttler, tenant_id) + frontend (NEXT_PUBLIC_ secret, CORS *, key hardcoded)
  infra/             ← NOVO: read-only — sshd_config, docker-compose, probe de porta 5432/6379
  compliance/        ← NOVO: LGPD (log de dado sensível, isolamento tenant, cripto)
  {auth,idor,race,stripe,tenant,docs}/ ← migrados ao novo contrato (camada + id determinístico)
packages/cli/        ← exige --target (um SaaS por run) ; registra novos agentes
packages/mcp-server/ ← idem ; expõe tools dos novos agentes
configs/targets.yaml ← suporta repoPath/infra/frontend/config opcionais por target
```

---

## 2. Contrato (forma final dos tipos novos em `core/types.ts`)

- `Finding` ganha: `camada: AgentCategory` (reusa o enum existente) e `status: 'open'|'suppressed'|'regression'`.
  `id` passa a ser determinístico: `stableFindingId(saas, camada, rule, location)` (sha256 truncado).
  `proposedFix?: { description; diff?; command?; riskOfApplying }` (preenchido só pelo LLM, **nunca aplicado**).
- `CheckResult { agent; camada; status: 'ok'|'error'|'skipped'; motivo?; durationMs; findings }`.
- `class SkippedCheck extends Error` → agente lança para sinalizar `skipped` com motivo
  (ex.: stack sem stripe, sem repoPath, sem infra). Qualquer outro throw → `error`. Sucesso → `ok`.
- `TargetHealth { repoAccessible; stagingResponding?; vpsReachable?; status }`.
- `AuditReport` substitui/estende `ScanReport`: `{ saas, timestamp, targetHealth, checks[], summary{ porSeveridade, regressoes, checksComErro[], checksPulados[] }, findings[], passed }`.
- `Target += { repoPath?; infra?{host,sshConfigPath,dockerComposePath}; frontend?{framework,envFiles}; config?{suppressions,severityThreshold} }`.

Tudo **aditivo** → build segue verde durante a migração agente-a-agente.

---

## 3. Fases (ordem de execução — validar contra **um** SaaS após cada uma)

**Cada fase termina com:** `pnpm build && pnpm test` verdes + 1 run real contra um SaaS
(sugestão: DoutorINSS ou VeriJus, por dado sensível) + commit.

### Fase 1 — Fundação: contrato + isolamento real
- Estender `types.ts` (Seção 2), `stableFindingId()`, `SkippedCheck`.
- `orchestrator.runCheckIsolated()`: cada agente roda em try/catch com **timeout** (`Promise.race`
  c/ `agent.timeoutMs`), medindo duração → produz `CheckResult`. Um check nunca derruba os outros
  (regra 4). Monta `AuditReport`.
- Migrar **HeadersAgent** (DAST mais simples) ao novo contrato como prova do ciclo completo.
- `reporter` passa a aceitar `AuditReport` (seção "checks que não rodaram" no MD).
- ✔ Aceite: agente que lança vira `status:error` isolado; demais terminam; MD/JSON declaram o que falhou.

### Fase 2 — Estado entre execuções (SQLite)
- `packages/store` com better-sqlite3: tabelas `FindingHistory(id,saas,camada,severidade,firstSeen,lastSeen,resolved,suppressed)` e `AuditRun(id,saas,timestamp,reportJson)`.
- `applyStatus()`: `id` reincidente após resolvido → `regression` (+conta `resumo.regressoes`);
  `id` em `config.suppressions` → `suppressed` (sai do ruído, **não some** do histórico); inédito → `open`.
- ✔ Aceite: rodar 2x o mesmo SaaS detecta regressão; suppression remove do topo sem apagar histórico.

### Fase 3 — Saúde do alvo
- `core/health.ts` + preflight no orchestrator: repo git válido? staging responde (se `url`)? vps alcançável (se `infra.host`)?
- `repoAccessible=false` quando há repoPath obrigatório → aborta com erro claro; staging/vps fora → checks dependentes `skipped` com motivo (regra: "não verificado" ≠ "seguro").
- ✔ Aceite: alvo fora do ar gera `skipped` declarado, nunca falso "passou".

### Fase 4 — Um-SaaS-por-vez + migrar agentes DAST restantes
- CLI: `--target` **obrigatório** no `scan` (remove varredura implícita dos 13 — regra 1). MCP idem.
- Migrar auth, idor, race, stripe, tenant, docs, skills ao contrato (camada + id determinístico).
- ✔ Aceite: `fracta scan` sem `--target` recusa; todos os agentes emitem id determinístico.

### Fase 5 — Novos agentes baseados em repositório (read-only)
Ordem: Dependencies → Secrets → Stack(SAST) → Infra → Compliance. Cada um:
wrapper fino sobre ferramenta consagrada, `skipped` quando falta input, **nunca escreve**.
- **Dependencies**: `npm audit --json` (severidade vem da ferramenta). [PROPÕE] bump/`audit fix` com risco.
- **Secrets**: `gitleaks detect --report-format json` no histórico. **SANITIZA** (tipo+local, nunca o valor).
  Checa `.env` no `.gitignore` e `.env.example` sem valores.
- **Stack(SAST)**: grep determinístico — Helmet no `main.ts`; `$queryRaw/$executeRaw` com **concatenação**;
  `ValidationPipe whitelist:true`; `@nestjs/throttler` em login e rotas LLM; query sem `tenant_id/owner_id`
  (heurística + flag p/ revisão). **+ Frontend (Seção 7 do guia)**: `NEXT_PUBLIC_*` com segredo,
  CORS `origin:'*'`, token hardcoded client-side, headers ausentes no `next.config`.
- **Infra**: 100% leitura — probe externo das portas 5432/6379 (responde de fora → `critical`);
  lê `sshd_config` (`PasswordAuthentication no`, `PermitRootLogin no`); `docker-compose` (`ports:` vs
  `expose:`, root, segredo em texto plano); `ufw`/`fail2ban` se legível. **Jamais executa nada.**
- **Compliance (LGPD)**: dado sensível (CNIS/previdenciário/criminal/cliente) em log texto plano;
  isolamento por tenant (cruza c/ Stack); cripto em repouso/trânsito.
- ✔ Aceite: cada novo agente roda isolado, read-only, e `skipped` sem input — nunca falso "seguro".

### Fase 6 — Borda LLM (opcional, por último)
- `packages/llm` (Anthropic SDK): (a) prioriza/ordena findings por contexto do SaaS;
  (b) redige `proposedFix` com `riskOfApplying` honesto. **Nunca** decide vulnerabilidade, muda
  severidade, aplica fix ou acessa o alvo. Sem API key → relatório completo, só sem priorização/redação.
- ✔ Aceite: desligar o LLM **não** impede detecção.

### Fase 7 — ReportConsolidator final
- Enriquecer MD: topo com critical/high, depois o resto, seção final transparente "checks que não rodaram"
  (erro + pulados), bloco de regressões destacado. JSON = `AuditReport` persistido (alimenta painel futuro).
- ✔ Aceite: JSON e Markdown idênticos em conteúdo; relatório declara explicitamente o não-verificado.

---

## 4. Rastreamento das 6 regras ↔ fases

| Regra inegociável | Onde é garantida |
|---|---|
| 1. Um SaaS por vez | Fase 4 (CLI `--target` obrigatório) |
| 2. Detectar ≠ corrigir | `proposedFix` nunca aplicado (F1 tipo, F6 redação) |
| 3. Read-only por padrão | Agentes F5 (Infra/Secrets/Stack só leem); DAST não escreve |
| 4. Isolamento entre checks | Fase 1 (`runCheckIsolated` + timeout) |
| 5. LLM só na borda | Detecção determinística (F5); LLM isolado em `packages/llm` (F6) |
| 6. Correção sempre gated | `proposedFix.riskOfApplying`; saída vai a relatório/PR (F6/F7) |

## 5. Critérios de aceite globais (Seção 10 do guia)
Marcados ✔ por fase acima. O sistema só é "robusto" quando: check que falha isola; input ausente vira
`skipped` (nunca falso seguro); nenhum agente escreve em produção; segredo nunca em texto plano;
JSON≡MD; regressão/supressão funcionam; LLM desligável; relatório declara o não-verificado; cada
agente é wrapper fino sobre ferramenta consagrada.
