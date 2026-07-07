import type { ScanDiff } from './diff.js'

/**
 * Formata o e-mail de ALERTA DE REGRESSÃO a partir de um diff. Puro (→ {subject,text,html}).
 * Honesto e direto: o que piorou, o link do relatório e o opt-out 1-clique (LGPD).
 * Transacional/leve — sem tracking pixel, sem imagem remota.
 */
export function formatAlertEmail(diff: ScanDiff, opts: { reportUrl: string; unsubUrl: string }): {
  subject: string
  text: string
  html: string
} {
  const host = safeHost(diff.url)
  const dropped = diff.gradeDelta === 'worsened' && diff.previousGrade && diff.currentGrade
  const subject = dropped
    ? `⚠️ A segurança de ${host} piorou (${diff.previousGrade} → ${diff.currentGrade})`
    : `⚠️ Novo problema de segurança em ${host}`

  const novos = diff.newFindings.map((f) => `• [${f.severity}] ${f.title}`)
  const linhaNota = dropped
    ? `Nota: ${diff.previousGrade} → ${diff.currentGrade}.`
    : `Nota: ${diff.currentGrade ?? 'não avaliada'} (surgiram achados novos).`

  const text = [
    `O Fracta re-escaneou ${host} e detectou uma regressão de segurança.`,
    ``,
    linhaNota,
    novos.length ? `\nNovos achados:\n${novos.join('\n')}` : '',
    ``,
    `Relatório completo: ${opts.reportUrl}`,
    ``,
    `— Fracta · monitoramento contínuo (você pediu para ser avisado).`,
    `Parar de receber estes alertas: ${opts.unsubUrl}`,
  ].join('\n')

  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const html = [
    `<div style="font-family:ui-sans-serif,system-ui,sans-serif;max-width:560px;color:#111">`,
    `<p>O <strong>Fracta</strong> re-escaneou <strong>${esc(host)}</strong> e detectou uma <strong>regressão de segurança</strong>.</p>`,
    `<p>${esc(linhaNota)}</p>`,
    novos.length ? `<p>Novos achados:</p><ul>${diff.newFindings.map((f) => `<li>[${esc(f.severity)}] ${esc(f.title)}</li>`).join('')}</ul>` : '',
    `<p><a href="${esc(opts.reportUrl)}">Ver o relatório completo →</a></p>`,
    `<hr style="border:none;border-top:1px solid #eee;margin:20px 0">`,
    `<p style="font-size:12px;color:#666">Fracta · monitoramento contínuo (você pediu para ser avisado).<br>`,
    `<a href="${esc(opts.unsubUrl)}" style="color:#666">Parar de receber estes alertas</a>.</p>`,
    `</div>`,
  ].join('')

  return { subject, text, html }
}

function safeHost(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}
