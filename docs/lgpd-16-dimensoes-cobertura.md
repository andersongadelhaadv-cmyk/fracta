# Revisão DPO — as 16 dimensões LGPD × o que o Fracta AUTOMATIZA

**Data:** 2026-07-10 · **Autor:** revisão de disciplina jurídica (Anderson, advogado) + confronto com o código.

> **Por que este documento existe.** O furo do Art. 33 (política que NEGA a transferência enquanto o
> código a faz) foi exatamente o tipo de gap que uma revisão jurídica pega — e pegou. Este é o passo
> seguinte: enumerar as **16 dimensões** da metodologia de adequação (a mesma da skill
> `lgpd-saas-adequacao`, aplicada ao próprio fracta.pro em `diagnostico-lgpd/2026-06-30/`) e confrontar,
> **sem otimismo**, o que o **scanner automático** (`ComplianceAgent` + tools de runtime) de fato mede
> contra o que exige **julgamento jurídico/processo**. Regra: **não afirmar cobertura que não se mede.**

## Distinção que precisa ficar clara

Há **dois produtos** sob o mesmo guarda-chuva "LGPD":
1. **Diagnóstico de 16 dimensões** (consultoria/skill `lgpd-saas-adequacao`) — cobre as 16, mas várias
   por análise **humana + documentos** (ROPA, TIA, plano de incidentes, designação de encarregado). É o
   que a home diz que rodamos "em nós mesmos, 100% adequado" — e há artefatos que provam (`diagnostico-lgpd/`).
2. **Scanner automático** (`scan_repo` / `fracta scan`) — determinístico, zero-token, roda no CI. Cobre
   **um subconjunto**: as dimensões **ancoradas no código/política**. As demais ele **não afirma** —
   marca como heurística e diz "não substitui adequação jurídica".

Este documento é sobre o item 2 (o scanner), para que ninguém leia "16 dimensões" e ache que o scanner
audita todas automaticamente no SEU repo.

## Confronto dimensão a dimensão

| # | Dimensão (artigo) | Scanner automatiza? | Como / ressalva |
|---|---|---|---|
| G001 | Transferência internacional **(Art. 33)** | ✅ **Forte** | `Check 7` política×código: contradição (nega+faz) e não-declarada. O diferencial. |
| G002 | Operadores/sub-processadores, DPA **(Art. 39)** | ✅ **Forte** | `Check 6` mapeia operadores por deps + `Check 7` acusa os ausentes da política. |
| G003 | ROPA / registro de operações **(Art. 37)** | ✅ **Bom** | `Check 5` monta rascunho de ROPA do `schema.prisma` (campos pessoais/sensíveis). |
| G012 | Política existe e cobre o essencial **(Art. 9º)** | ✅ **Bom** | `findPolicyDoc` localiza e pontua a política publicada; base p/ os Checks 7. |
| G008 | Encarregado/DPO **(Art. 41)** | ✅ **Novo (round DPO)** | `lgpd-policy-missing-dpo`: acusa política sem menção a Encarregado/DPO. *Era só sinal de score; virou achado.* |
| G010 | Direitos do titular **(Art. 18)** | ✅ **Novo (round DPO)** | `lgpd-policy-missing-rights`: acusa política sem descrição de acesso/correção/exclusão/portabilidade. |
| G009 | Segurança/criptografia **(Art. 46)** | 🟡 **Parcial** | `Check 4` (TLS/HTTPS não evidenciado) + senha sem hashing + dado sensível em log. Foco em-trânsito; repouso não é medido. |
| G011 | Cookies/rastreadores **(Art. 7º/8º)** | 🟡 **Runtime (tool à parte)** | `passive_scan` + `verify_consent` (browser real) — não é o `ComplianceAgent`, exige rodar contra a URL. |
| G005 | Consentimento **(Art. 8º)** | 🟡 **Parcial/runtime** | `verify_consent` prova tracker pré-consentimento; registro granular de consentimento = manual. |
| G007 | Retenção/eliminação **(Art. 15/16)** | 🟡 **Só recomenda** | ROPA sugere definir retenção; não há prazo no código para medir. Ressalva honesta. |
| G013 | Minimização **(Art. 6º)** | 🟡 **Só expõe** | O inventário lista todos os campos pessoais; o juízo de "necessidade" é humano. |
| G004 | Plano de resposta a incidentes **(Art. 48)** | ❌ **Não (processo)** | Documento de governança — fora do escopo de um scanner estático. Dito honestamente. |
| G006 | TIA / legítimo interesse **(Art. 7º IX)** | ❌ **Não (documento legal)** | Exige o TIA redigido; não é code-detectável. |
| G014 | Decisões automatizadas **(Art. 20)** | ⚪ **N/A** | Depende do contexto de negócio; não inferível estático. |
| G015 | RIPD/DPIA **(Art. 38)** | ⚪ **N/A** | Documento de impacto; humano. |
| G016 | Crianças e adolescentes **(Art. 14)** | ⚪ **N/A** | Depende do público-alvo; não inferível estático. |

## Placar honesto do scanner automático

- **Automatiza com solidez: 6** (G001, G002, G003, G012, G008, G010) — as dimensões ancoradas em código/política.
- **Parcial / runtime / só recomenda: 5** (G009, G011, G005, G007, G013) — o scanner toca, mas o fechamento é humano ou exige rodar contra a URL.
- **Não automatiza — processo/documento/legal: 5** (G004, G006, G014, G015, G016) — corretamente fora do escopo de um scanner estático; **o Fracta diz isso, não finge cobrir**.

**Fechamento desta rodada (round DPO):** as duas dimensões code-detectáveis que antes eram só "sinal de
score" viraram achado medido — **Encarregado (Art. 41)** e **direitos do titular (Art. 18)** — com TDD
(`declaresDpo`/`declaresDataSubjectRights`, `info/low`, nunca reprovam, com ressalva de heurística de texto).
Os 5 "parciais" e os 5 "não-automatiza" ficam como **ressalva honesta no relatório**, não como cobertura
afirmada. É essa honestidade — dizer o que NÃO se mede — que sustenta a marca.
