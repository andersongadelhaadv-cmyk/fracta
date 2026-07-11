# Runbook — a rodada cheia (N≈400)

O piloto provou a infra. Esta é a operação da rodada completa. **Escolha do veículo importa:**

## Veículo (onde rodar)

| Opção | SAST (semgrep) | Risco | Recomendação |
|---|---|---|---|
| **Docker Linux (isolado)** | ✅ rápido | nenhum | **preferido** — `bench/runner/compose.yml` |
| Runner CI dedicado (Linux) | ✅ | nenhum | bom p/ agendar; chunk se >6h |
| VPS de produção (compartilhada da frota) | ✅ | 🔴 **alto** — hospeda a FROTA inteira | **evitar** — scan pesado starva os SaaS vivos |
| Windows local | ❌ semgrep estoura 120s → `skipped` | nenhum | só p/ LGPD/secrets, não SAST |

> **Nunca** rodar os 4 workers de scan na VPS compartilhada sem janela dedicada — degradaria a frota.
> Se for a VPS, use `--concurrency 1`, `mem_limit`, e fora de horário de pico.

## Pré-requisitos p/ recall REAL (senão os agentes reportam `skipped` — honesto, mas piso)

- **gitleaks** no PATH → recall de segredos real (senão só o STACK pega provider-shaped).
- **rede + lockfile** nos alvos → recall de deps (npm audit). No modo isolado sem rede, deps = `skipped`.
- **semgrep** (já embarcado na imagem) rodando em Linux → SAST real (no Windows, `skipped`).

## Passos

```bash
# 1. Corpus congelado (já versionado se rodou `bench:corpus`). Verifique as âncoras:
node bench/corpus/freeze.mjs            # ok / drift / vanished

# 2. Rodada cheia isolada (Docker Linux, retomável — relança e pula os já feitos):
GH_TOKEN=$TOKEN docker compose -f bench/runner/compose.yml run --rm bench

#    ou local Linux/CI:
pnpm build && pnpm bench:run            # clona@SHA + escaneia; results/ é retomável

# 3. Cross-check incumbentes (mesmos SHAs; Linux roda limpo):
node bench/crosscheck/run-incumbents.mjs

# 4. Precisão: gere a fila, ROTULE à mão (a parte cara), salve labels.csv:
node bench/report/label-queue.mjs --per 57      # n p/ IC ~±13%
#    → humano preenche `verdict` (TP/FP) em results/label-queue.csv → salva como results/labels.csv

# 5. Relatório (recall + precisão/IC + robustez + comparativa + "o que não mede"):
pnpm bench:report                       # bench/report/report.md + report.json
```

## Definição de pronto
`pnpm bench:report` reproduz o número a partir de `results/summary.jsonl` (redigido, versionado).
Qualquer terceiro com o repo + token GitHub reproduz — esse é o critério.

## Findings do benchmark a investigar (rodada SEPARADA, engine congelada)
Fixtures `art33` / `operador` / `sem-política` não foram flagrados nos fixtures mínimos.
Antes de concluir "gap de engine", torne os fixtures realistas (política + código completos) e
re-meça — **sem** tocar na engine durante a medição.
