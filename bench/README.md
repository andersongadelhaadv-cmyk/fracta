# `bench/` — Corpus de validação em escala do Fracta

Mede **precisão, recall e taxa de falsos-positivos** do Fracta contra um corpus
de ~400 repositórios públicos reais, com metodologia declarada e reproduzível por
terceiro. É o scale-up honesto do benchmark N=1 de [`docs/benchmark.md`](../docs/benchmark.md)
(15/18 vs gitleaks/semgrep/trivy).

## Trava metodológica (não negociável)

- **A engine de detecção do Fracta é CONGELADA durante a medição.** Bug ou FP
  sistemático revelado aqui vira *finding registrado*, não um fix — quem ajusta a
  régua durante a medição invalida a medição.
- Repos do corpus são **READ-ONLY absolutos**: clonar `--depth 1` no SHA congelado,
  escanear estaticamente, nunca modificar, nunca `npm install`, nunca executar o
  código deles, nunca abrir issue/PR.
- **100% SAST/repo. Zero DAST** contra terceiros.

## Fluxo (Definição de Pronto)

```
pnpm bench:corpus   # Fase 1 — gera/atualiza corpus/manifest.yaml (query GH declarada, SHA congelado)
pnpm bench:run      # Fase 2 — clona@SHA + scan_repo → results/{repo}/raw.json (resumível)
pnpm bench:report   # Fase 4 — reproduz o NÚMERO a partir de results/summary.jsonl (minutos)
pnpm bench:full     # tudo de ponta a ponta (horas)
```

`bench:report` reproduz o número em minutos porque lê o **summary redigido versionado**
(`results/summary.jsonl`) — não precisa re-clonar 400 repos. Só `bench:full` faz a rodada cara.

## Camadas de ground truth (Fase 3 — a parte cara)

| Camada | O que dá | Onde |
|---|---|---|
| **a) Fixtures plantados** | **recall exato** (gabarito conhecido) | `fixtures/` + `fixtures/catalog.json` (oráculo `{file,line,rule}`) |
| **b) Amostragem rotulada** | **precisão** com IC 95% | `report/label-queue.mjs` → humano → `results/labels.csv` |
| **c) Cross-check incumbentes** | **concordância comparativa** (NÃO é verdade) | `crosscheck/` |

Regra da camada (b): a ferramenta **propõe** o rótulo; o **humano confirma**. `detect ≠ correct`
vale para rótulo. A precisão sai da amostra rotulada, com `n` e IC declarados — nunca um ponto sem erro.

## Reprodutibilidade

`corpus/manifest.yaml` congela, por repo: `owner/name`, `sha` (HEAD resolvido) e `treeHash`
(hash do conteúdo clonado). Um terceiro confere que pegou **os mesmos bits**. Repos que somem
(deletados/privados) NÃO são removidos do manifest — viram linha `vanished` no relatório de robustez.

## O QUE ESTE BENCHMARK **NÃO** MEDE

Declarar limites é a marca do Fracta. Este benchmark **não** mede:

- **DAST / runtime / autenticação / IDOR** — é 100% estático de repositório. A verificação
  em runtime (tracker pré-consentimento, CSP efetiva, auth) é missão separada.
- **A população real de clientes.** O corpus é de repos **públicos**; SaaS privados (onde o
  Fracta roda de verdade) tendem a ter segredos vivos e código que não aparece em público.
  Recall/FPR aqui **não transferem 1:1** — é uma estimativa de generalização, não a verdade da base paga.
- **Precisão além da amostra rotulada.** Fora da amostra, precisão é *estimada* (IC), não contada.
- **Recall de segredos/deps quando a ferramenta-alvo está ausente.** Sem `gitleaks` no PATH ou
  sem lockfile, os agentes reportam `skipped` (honestidade), e o relatório separa
  `skipped` de `clean` — 0 achados por tool-ausente ≠ 0 achados por repo-limpo.
