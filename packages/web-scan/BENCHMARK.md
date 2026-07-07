# Fracta — benchmark de correção (CSP + cookies)

Precisão/recall/F1 dos detectores **determinísticos** do Fracta, medidos sobre um corpus
rotulado por **ground-truth externo** (CSP spec / OWASP / MDN). O corpus é honesto por design:
qualquer regra que ainda não cobríssemos entraria como false-negative (não é 100% por construção).
Reproduzível: `BENCH_WRITE=1 npx vitest run src/__tests__/bench.test.ts`.

## Resultado (24 casos)

| Categoria | Casos | Precisão | Recall | F1 |
|---|---|---|---|---|
| CSP | 16 | 100.0% | 100.0% | 1.000 |
| Cookies | 8 | 100.0% | 100.0% | 1.000 |
| **Geral** | 24 | 100.0% | 100.0% | 1.000 |

**Precisão** = dos achados que emitimos, quantos são corretos (sem falso-positivo).
**Recall** = dos problemas reais, quantos pegamos.

## Gaps conhecidos (false-negatives — próximos a cobrir)
_Nenhum gap conhecido — todas as regras do corpus são cobertas._

## Por regra

| Regra | TP | FP | FN | Precisão | Recall |
|---|---|---|---|---|---|
| `cookie-flags:__Host-sid` | 1 | 0 | 0 | 100.0% | 100.0% |
| `cookie-flags:ruim` | 1 | 0 | 0 | 100.0% | 100.0% |
| `cookie-flags:sid` | 4 | 0 | 0 | 100.0% | 100.0% |
| `cookie-flags:token` | 1 | 0 | 0 | 100.0% | 100.0% |
| `csp-broad-script-src` | 3 | 0 | 0 | 100.0% | 100.0% |
| `csp-no-base-uri` | 3 | 0 | 0 | 100.0% | 100.0% |
| `csp-no-default-src` | 2 | 0 | 0 | 100.0% | 100.0% |
| `csp-no-form-action` | 3 | 0 | 0 | 100.0% | 100.0% |
| `csp-no-frame-ancestors` | 3 | 0 | 0 | 100.0% | 100.0% |
| `csp-no-script-src` | 1 | 0 | 0 | 100.0% | 100.0% |
| `csp-object-src` | 3 | 0 | 0 | 100.0% | 100.0% |
| `csp-unsafe-eval` | 2 | 0 | 0 | 100.0% | 100.0% |
| `csp-unsafe-inline-script` | 2 | 0 | 0 | 100.0% | 100.0% |
| `csp-unsafe-inline-style` | 1 | 0 | 0 | 100.0% | 100.0% |

_Gerado deterministicamente pelo harness de benchmark (`packages/web-scan/src/__tests__/bench.test.ts`)._
