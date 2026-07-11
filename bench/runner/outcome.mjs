// Classifica o desfecho de um scan em um repo → distribuição de robustez do relatório.
// ok / timeout / crash / oom. Puro e testável.
const OOM = /out of memory|heap|ENOMEM|\boom\b|allocation failed/i

export function classifyOutcome({ error, timedOut, report } = {}) {
  if (timedOut) return 'timeout'
  const msg = error instanceof Error ? error.message : typeof error === 'string' ? error : ''
  if (error) return OOM.test(msg) ? 'oom' : 'crash'
  if (report) return 'ok'
  return 'crash'
}
