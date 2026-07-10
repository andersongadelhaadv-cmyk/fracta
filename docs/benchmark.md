# Benchmark — Fracta vs. gitleaks / semgrep / trivy

**Data:** 2026-07-09 · **Método:** repo plantado com gabarito conhecido, cada ferramenta rodada
lado-a-lado, recall/precisão contados à mão. Reprodutível — o repo e os comandos estão abaixo.

> **Honestidade primeiro.** O Fracta **não substitui** gitleaks/semgrep — ele os **invoca** (wrap) e
> soma uma camada que eles não têm. Este benchmark mede exatamente isso: (1) que o Fracta **não perde
> recall** ao orquestrar os incumbentes e (2) que a camada **LGPD-nativa é a única que detecta** uma
> classe inteira de risco que nenhum dos três enxerga. A pergunta "por que não só o gitleaks?" tem
> resposta medida, não afirmada.

## Repositório plantado — gabarito (18 itens)

| Classe | # | Itens |
|---|---|---|
| Segredos versionados | 6 | AWS key, AWS secret, Stripe `sk_live`, GitHub PAT, chave genérica alta-entropia, chave RSA privada |
| SAST (código) | 4 | SQLi (concat), command injection (`exec`), `eval()` de input, XSS refletido |
| Dependências vulneráveis (CVE) | 3 | `lodash@4.17.4`, `axios@0.18.0`, `jsonwebtoken@8.5.1` |
| **LGPD** | 5 | Art.33 (política **nega** transf. intl, código a faz), operador não-declarado (Sentry), dado sensível em log, ROPA/inventário (Prisma), senha sem hashing |

Todos os "segredos" são **sintéticos** (aleatórios, não são credenciais reais).

## Resultados — recall (achados corretos / plantados)

| Ferramenta | Segredos (6) | SAST (4) | Deps (3) | **LGPD (5)** | **Total (18)** | Precisão |
|---|---|---|---|---|---|---|
| gitleaks 8.30.1 | **6** | 0 | 0 | 0 | 6 | 100% (6/6) |
| semgrep 1.168 `p/security-audit` | 0 | 1 | 0 | 0 | 1 | 100% (1/1) |
| trivy (fs) | 0 | 0 | **3** | 0 | 3 | 100% (3/3 pkgs) |
| **Fracta 0.1.20** | **6** | 1 | **3** | **5** | **15** | ~100% (0 FP hard) |

### Leitura honesta
- **Segredos:** Fracta = gitleaks (o invoca 1:1) → **6/6, sem perda**. Ainda adiciona checagens de
  higiene (`.env`/`.gitignore`) que o gitleaks sozinho não faz.
- **SAST:** Fracta = semgrep, no ruleset que ele embarca (`p/security-audit`) → **1/4**. É um teto de
  **config** (o pack é conservador: alta precisão, recall baixo), não um bug do Fracta. Com `p/default`
  o próprio semgrep sobe para **3/4** (pega `eval`/XSS; só o SQLi via `pg` escapa). *Ver "Ajuste em
  aberto" abaixo.*
- **Deps/CVE:** Fracta = `npm audit` → **3/3 pacotes**, paridade com o trivy no nível de pacote (o
  trivy enumera mais CVEs individuais do mesmo pacote; a ação — atualizar o pacote — é a mesma).
- **LGPD (o fosso):** **5/5, e o Fracta é o único** que detecta **qualquer** item desta classe.
  gitleaks/semgrep/trivy = **0/5**. Estruturalmente cegos: nenhum lê política×código, ROPA, operadores
  ou Art.33. Aqui não há incumbente para "trocar" — só o Fracta faz.
- **Honestidade (propriedade que nenhum incumbente tem):** quando o semgrep não pôde rodar (timeout no
  Windows), o Fracta reportou `SEMGREP skipped` — nunca um falso "limpo". Ausência de achado ≠ seguro.

**Conclusão:** o Fracta cobre a **união** dos três (≥ recall de cada um na sua área) **e** adiciona a
camada LGPD que vale 5/5 sozinha, com honestidade e IDs determinísticos que os incumbentes não dão.
A tese "LGPD + SAST + segredos + honestidade num lugar" é **medida**, não afirmada.

### Ajuste do config SAST — MEDIDO e DECIDIDO (2026-07-10)
O default `p/security-audit` pega 1/4 no repo plantado; `p/default` pega 3/4 (+`eval`/XSS). Antes de
trocar às cegas, medimos o **custo de precisão em código REAL** (anti-cry-wolf):
- 19 arquivos reais limpos (Veredicto): p/default **0 novas** (não espalha FP em código limpo — bom).
- 59 arquivos reais (zap-api services): p/security-audit 0 → p/default **+1**, e essa 1 é
  `detect-non-literal-regexp` — regra **notoriamente de baixa precisão** (ReDoS só importa com input do
  usuário). Ou seja: em código real, o ganho do p/default é dominado por **ruído**, não pelo eval/XSS
  (que quase só aparece em fixture).

**Decisão:** manter `p/security-audit` como default (alta precisão — a postura anti-cry-wolf do produto).
Quem quer SAST agressivo já tem o tunable **`FRACTA_SEMGREP_CONFIG=p/default`** (existe desde sempre).
Documentado como escolha informada, com os números na mesa — não como default arriscado.

## Reprodução (um comando)

```bash
bash docs/benchmark-repo/run.sh /tmp/fracta-bench
```

Planta o repo (gabarito machine-checkable em `docs/benchmark-repo/ground-truth.json`), roda
gitleaks/semgrep/trivy/npm-audit/fracta e imprime a tabela de recall via `score.mjs`. Ferramentas
ausentes entram como 0. Detalhes e a nota de honestidade (o scorer é um piso conservador para o Fracta;
esta tabela conferida à mão é a canônica) em `docs/benchmark-repo/README.md`.
