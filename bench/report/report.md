# Relatório de validação em escala — Fracta

**Gerado:** 2026-07-11T18:54:12.983Z · **Registros:** 51 (21 repos reais + 30 fixtures)

> Reproduzível: `pnpm bench:report` reconstrói estes números a partir de `results/summary.jsonl` (redigido, versionado) — sem re-clonar. A rodada cara é `bench:full`.

## Robustez (distribuição de desfechos)

| Desfecho | Repos |
|---|---|
| ok | 51 |

Reprodutibilidade do corpus: 3 ok · 0 drift · 0 sumiram (de 3 verificados).

## Recall (fixtures plantados — gabarito conhecido)

| Categoria | Recall | IC 95% |
|---|---|---|
| secret | 50% | [24–76%] (n=10) |
| sast | 13% | [2–47%] (n=8) |
| deps | 0% | [0–39%] (n=6) |
| lgpd | 50% | [19–81%] (n=6) |
| **geral** | **30%** | **[17–48%] (n=30)** |

> ⚠️ Honestidade: SEMGREP pulou em 0 fixture(s) e DEPENDENCIES em 30 — `skipped` **≠** `clean`. SAST via semgrep é lento no Windows (roda em Linux/CI, ver Docker); deps exige lockfile+rede. Recall dessas categorias aqui é **piso**, não teto.

<details><summary>Itens não detectados (21)</summary>

- sec-aws-secret/src/aws.ts:2 (aws-secret-access-key)
- sec-generic/src/cfg.ts:2 (generic-api-key)
- sec-slack/src/slack.ts:2 (slack-access-token)
- sec-jwt/src/jwt.ts:2 (jwt)
- sec-gcp/src/gcp.ts:2 (gcp-api-key)
- sast-sqli/src/db.ts:3 (sql-injection)
- sast-eval/src/calc.ts:1 (eval-injection)
- sast-xss/src/render.ts:1 (reflected-xss)
- sast-pathtrav/src/file.ts:2 (path-traversal)
- sast-md5/src/hash.ts:2 (weak-hash)
- sast-rand/src/token.ts:1 (insecure-random)
- sast-ssrf/src/proxy.ts:1 (ssrf)
- deps-lodash/package.json:6 (cve:lodash)
- deps-axios/package.json:6 (cve:axios)
- deps-jwt/package.json:6 (cve:jsonwebtoken)
- deps-minimist/package.json:6 (cve:minimist)
- deps-marked/package.json:6 (cve:marked)
- deps-nodefetch/package.json:6 (cve:node-fetch)
- lgpd-art33/src/analytics.ts:2 (lgpd-art33-contradiction)
- lgpd-operador/src/monitor.ts:2 (lgpd-undeclared-operator)
- lgpd-sempolitica/prisma/schema.prisma:3 (lgpd-missing-privacy-policy)

</details>

## Precisão / taxa de falsa-descoberta (amostra rotulada em repos reais)

_Pendente rotulagem humana._ Gere a fila com `node bench/report/label-queue.mjs`, preencha `verdict` (TP/FP) e salve como `results/labels.csv`. A ferramenta **propõe**; o humano **confirma**.

## Corpus por estrato

| Estrato | Repos | Findings |
|---|---|---|
| br-lgpd | 3 | 147 |
| django-python | 3 | 136 |
| laravel-php | 3 | 6 |
| monorepo-large | 3 | 327 |
| nestjs-node | 3 | 228 |
| nextjs | 3 | 8 |
| wordpress-legacy | 3 | 11 |

## Comparativa vs incumbentes

Cross-check disponível sobre 30 alvo(s) (`results/incumbents.json`). Incumbentes são presos à pista (gitleaks→segredos, semgrep→SAST, trivy→deps); **LGPD = 0 para todos, não-zero só no Fracta**. A tabela conferida à mão (15/18) segue canônica em `docs/benchmark.md`.


## O QUE ESTE BENCHMARK **NÃO** MEDE

- **DAST / runtime / auth / IDOR** — é 100% estático de repositório.
- **A população real de clientes.** Corpus público ≠ SaaS privados (onde o Fracta roda); recall/FDR **não transferem 1:1**. É estimativa de generalização.
- **Precisão fora da amostra rotulada** — é estimada (IC), não contada.
- **Categorias com tool ausente** (semgrep no Windows, deps sem lockfile/rede) — reportadas como `skipped`, nunca `clean`.

