# Briefing para revisão DPO EXTERNA — Fracta

**Objetivo:** um DPO/advogado **externo** (não o dono do produto) fecha, em ~2–3h, uma revisão das
alegações LGPD do Fracta. É o passo que remove o conflito de interesse (o Anderson é advogado, mas é o
dono) e pega o tipo de furo que só olho jurídico externo pega — como o do **Art. 33** já pegou.

## O que é o Fracta (1 parágrafo)
Auditor de segurança + LGPD **read-only** para SaaS. Duas superfícies relevantes aqui: (1) o **scanner
automático** (`scan_repo`), que confere código × política e emite achados determinísticos; (2) o
**diagnóstico manual de 16 dimensões** (metodologia `lgpd-saas-adequacao`), aplicado ao próprio
fracta.pro, cujos artefatos estão em `diagnostico-lgpd/2026-06-30/` (ROPA, TIA, plano de incidentes,
designação de encarregado).

## Material para a revisão (tudo versionado)
- `docs/lgpd-16-dimensoes-cobertura.md` — o confronto dimensão a dimensão (o que o scanner automatiza vs
  o que exige julgamento humano).
- `diagnostico-lgpd/2026-06-30/diagnostico/relatorio-adequacao.md` — o diagnóstico das 16 dimensões (G001–G016).
- Os detectores LGPD (fonte): `packages/agents/compliance/src/lgpd-policy.ts` e `lgpd-inventory.ts`.

## Perguntas objetivas (sim/não + justificativa) — é isto que pedimos ao DPO externo

### A. Sobre as ALEGAÇÕES públicas (home + blog)
1. A frase "auditoria completa de LGPD (16 dimensões) … 100% adequado, em nós mesmos" está **corretamente
   escopada** ao diagnóstico MANUAL (com artefatos), sem induzir o leitor a achar que o *scanner* audita
   as 16 no repo dele? Se não, como reescrever?
2. O tratamento de transferência internacional do próprio Fracta (Stripe/infra) está de fato ancorado em
   hipótese válida do **Art. 33** e declarado na política? (é a alegação central do diferencial)

### B. Sobre o que o SCANNER afirma detectar (risco de overclaim)
3. Os achados automáticos usam a âncora legal correta? Conferir: `lgpd-policy-intl-contradicted` (Art. 33),
   `lgpd-operators-*` (Art. 39/9º), `lgpd-data-inventory` (Art. 37), `lgpd-policy-missing-dpo` (Art. 41),
   `lgpd-policy-missing-rights` (Art. 18), `sensitive-in-log` (Art. 46), `password-no-hashing` (Art. 46).
4. Há alguma dimensão onde o scanner **afirma cobertura** que na verdade exige julgamento jurídico (o
   pecado que queremos evitar)? A auto-avaliação diz que automatiza ~6/16 com solidez e é honesto sobre
   o resto — **confirma ou corrige** essa divisão.
5. As **negações** (heurística `INTL_DENIAL`) e a desambiguação "cita Art. 33 = declaração" estão
   juridicamente corretas? (foi exatamente aqui que nasceu e se corrigiu o furo original)

### C. Dimensões marcadas como PARCIAIS ou N/A — estão certas?
6. Retenção (Art. 15/16), consentimento granular (Art. 8º), minimização (Art. 6º) estão corretamente como
   "parcial / recomenda"? Alguma é code-detectável e deveria virar achado (como Art.41/Art.18 viraram)?
7. RIPD/DPIA (Art. 38), decisões automatizadas (Art. 20), crianças (Art. 14) estão corretamente como N/A
   para um scanner estático, ou algum é inferível e vale um sinal?

## Saída esperada da revisão
Um parecer curto (pode ser e-mail) com: (a) as respostas sim/não acima; (b) qualquer **overclaim** a
corrigir na home/relatório; (c) qualquer dimensão code-detectável faltando. **Cada gap vira issue com
TDD** no repo (red→green→re-prova), do mesmo jeito que o Art. 33 e o Art.41/Art.18 viraram.

> Regra de honestidade do produto: **não afirmar cobertura que não se mede.** Se a revisão externa achar
> uma afirmação forte demais, a correção é baixar a afirmação — não inflar a heurística.
