# Relatório de validação em escala — Fracta

**Gerado:** 2026-07-11T13:23:11.532Z · **Registros:** 3 (3 repos reais + 0 fixtures)

> Reproduzível: `pnpm bench:report` reconstrói estes números a partir de `results/summary.jsonl` (redigido, versionado) — sem re-clonar. A rodada cara é `bench:full`.

## Robustez (distribuição de desfechos)

| Desfecho | Repos |
|---|---|
| timeout | 2 |
| ok | 1 |

Reprodutibilidade do corpus: 3 ok · 0 drift · 0 sumiram (de 3 verificados).

## Recall (fixtures plantados — gabarito conhecido)

| Categoria | Recall | IC 95% |
|---|---|---|
| secret | 10% | [2–40%] (n=10) |
| sast | 0% | [0–32%] (n=8) |
| deps | 0% | [0–39%] (n=6) |
| lgpd | 50% | [19–81%] (n=6) |
| **geral** | **13%** | **[5–30%] (n=30)** |

> ⚠️ Honestidade: SEMGREP pulou em 30 fixture(s) e DEPENDENCIES em 30 — `skipped` **≠** `clean`. SAST via semgrep é lento no Windows (roda em Linux/CI, ver Docker); deps exige lockfile+rede. Recall dessas categorias aqui é **piso**, não teto.

<details><summary>Itens não detectados (26)</summary>

- sec-aws-key/src/aws.ts:2 (aws-access-key-id)
- sec-aws-secret/src/aws.ts:2 (aws-secret-access-key)
- sec-github-pat/src/gh.ts:2 (github-pat)
- sec-generic/src/cfg.ts:2 (generic-api-key)
- sec-slack/src/slack.ts:2 (slack-access-token)
- sec-npm/src/.npmrc:2 (npm-access-token)
- sec-jwt/src/jwt.ts:2 (jwt)
- sec-gcp/src/gcp.ts:2 (gcp-api-key)
- sec-rsa/src/id_rsa:1 (private-key)
- sast-sqli/src/db.ts:3 (sql-injection)
- sast-cmdi/src/sh.ts:2 (command-injection)
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
| br-lgpd | 2 | 0 |
| nextjs | 1 | 2 |

## Comparativa vs incumbentes

_Cross-check não rodado (`node bench/crosscheck/run-incumbents.mjs`). Canônica hand-checked: `docs/benchmark.md` (15/18)._


## O QUE ESTE BENCHMARK **NÃO** MEDE

- **DAST / runtime / auth / IDOR** — é 100% estático de repositório.
- **A população real de clientes.** Corpus público ≠ SaaS privados (onde o Fracta roda); recall/FDR **não transferem 1:1**. É estimativa de generalização.
- **Precisão fora da amostra rotulada** — é estimada (IC), não contada.
- **Categorias com tool ausente** (semgrep no Windows, deps sem lockfile/rede) — reportadas como `skipped`, nunca `clean`.

