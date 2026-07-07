import { describe, it, expect } from 'vitest'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { analyzeCsp } from '@fracta/agent-headers'
import { findCookieIssues } from '../cookie-check.js'
import { CSP_CORPUS, COOKIE_CORPUS, CSP_GAP_RULES } from '../bench/corpus.js'
import { evaluate, evaluatePerRule, type EvalCase, type Metrics } from '../bench/metrics.js'

// ── actual = o que o detector REAL emite (rule ids), por caso ──────────────────
const cspCases: EvalCase[] = CSP_CORPUS.map((c) => ({
  expected: new Set(c.expected),
  actual: new Set(analyzeCsp(c.csp).map((i) => i.rule)),
}))
const cookieCases: EvalCase[] = COOKIE_CORPUS.map((c) => ({
  expected: new Set(c.expected),
  actual: new Set(
    findCookieIssues(c.setCookie, 'bench', 'bench').map((f) => `cookie-flags:${f.title.split(': ').slice(1).join(': ')}`),
  ),
}))

const csp = evaluate(cspCases)
const cookie = evaluate(cookieCases)
const overall = evaluate([...cspCases, ...cookieCases])
const perRule = evaluatePerRule([...cspCases, ...cookieCases])

const pct = (n: number) => `${(n * 100).toFixed(1)}%`

describe('benchmark de correção (CSP + cookies)', () => {
  // Guarda de regressão: precisão ~perfeita (não devemos falso-positivar) e recall alto
  // (os casos-gap deliberados o mantêm < 100% de propósito). Regressão real quebra aqui.
  it('precisão não regride (sem falso-positivo nas regras que cobrimos)', () => {
    expect(csp.precision).toBeGreaterThanOrEqual(0.99)
    expect(cookie.precision).toBeGreaterThanOrEqual(0.99)
  })

  it('recall ~perfeito (sem gaps conhecidos, pegamos tudo do corpus)', () => {
    expect(overall.recall).toBeGreaterThanOrEqual(0.99)
  })

  it('os ÚNICOS false-negatives são as regras-gap conhecidas (nada regrediu escondido)', () => {
    const fnRules = Object.entries(perRule)
      .filter(([, m]) => m.fn > 0)
      .map(([rule]) => rule)
    // todo FN precisa ser uma regra-gap declarada — com CSP_GAP_RULES vazio, isso exige ZERO FN
    for (const r of fnRules) expect(CSP_GAP_RULES).toContain(r)
  })

  it('escreve o relatório quando BENCH_WRITE=1', () => {
    if (!process.env.BENCH_WRITE) return
    const md = renderReport({ csp, cookie, overall, perRule })
    writeFileSync(fileURLToPath(new URL('../../BENCHMARK.md', import.meta.url)), md)
    writeFileSync(
      fileURLToPath(new URL('../../benchmark.json', import.meta.url)),
      JSON.stringify({ csp, cookie, overall, perRule, cases: cspCases.length + cookieCases.length }, null, 2),
    )
  })
})

function renderReport(r: { csp: Metrics; cookie: Metrics; overall: Metrics; perRule: Record<string, Metrics> }): string {
  const row = (label: string, n: number, m: Metrics) =>
    `| ${label} | ${n} | ${pct(m.precision)} | ${pct(m.recall)} | ${m.f1.toFixed(3)} |`
  const perRuleRows = Object.entries(r.perRule)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([rule, m]) => `| \`${rule}\` | ${m.tp} | ${m.fp} | ${m.fn} | ${pct(m.precision)} | ${pct(m.recall)} |`)
    .join('\n')
  const gaps = CSP_GAP_RULES.length
    ? CSP_GAP_RULES.map((g) => `- \`${g}\` — regra que um scanner completo emite e o Fracta ainda **não** cobre.`).join('\n')
    : '_Nenhum gap conhecido — todas as regras do corpus são cobertas._'
  return `# Fracta — benchmark de correção (CSP + cookies)

Precisão/recall/F1 dos detectores **determinísticos** do Fracta, medidos sobre um corpus
rotulado por **ground-truth externo** (CSP spec / OWASP / MDN). O corpus é honesto por design:
qualquer regra que ainda não cobríssemos entraria como false-negative (não é 100% por construção).
Reproduzível: \`BENCH_WRITE=1 npx vitest run src/__tests__/bench.test.ts\`.

## Resultado (${CSP_CORPUS.length + COOKIE_CORPUS.length} casos)

| Categoria | Casos | Precisão | Recall | F1 |
|---|---|---|---|---|
${row('CSP', CSP_CORPUS.length, r.csp)}
${row('Cookies', COOKIE_CORPUS.length, r.cookie)}
${row('**Geral**', CSP_CORPUS.length + COOKIE_CORPUS.length, r.overall)}

**Precisão** = dos achados que emitimos, quantos são corretos (sem falso-positivo).
**Recall** = dos problemas reais, quantos pegamos.

## Gaps conhecidos (false-negatives — próximos a cobrir)
${gaps}

## Por regra

| Regra | TP | FP | FN | Precisão | Recall |
|---|---|---|---|---|---|
${perRuleRows}

_Gerado deterministicamente pelo harness de benchmark (\`packages/web-scan/src/__tests__/bench.test.ts\`)._
`
}
