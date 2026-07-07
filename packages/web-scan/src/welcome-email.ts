/**
 * E-mail de BOAS-VINDAS / confirmação do monitoramento (opt-in). Puro (→ {subject,text,html}).
 * Tom Fracta via header dark (imagem) + acento ciano; corpo claro/legível (dark body quebra em
 * vários clientes de e-mail). `headerSrc` = URL hospedada OU `cid:...` (imagem inline).
 */
export function formatWelcomeEmail(opts: { url: string; unsubUrl: string; headerSrc: string }): {
  subject: string
  text: string
  html: string
} {
  const host = safeHost(opts.url)
  const CY = '#0e8f88' // ciano acessível sobre fundo claro (o header é que carrega o ciano vívido)

  const subject = `Você está monitorando ${host} — Fracta`

  const text = [
    `Pronto — o Fracta está de olho em ${host}.`,
    ``,
    `A partir de agora, a gente re-escaneia esse site periodicamente e te avisa por e-mail`,
    `SE a segurança piorar — a nota cair ou surgir um problema novo. Nada de spam: só quando`,
    `algo realmente muda pra pior.`,
    ``,
    `Determinístico, sem palpite de IA — o mesmo motor do fracta.pro.`,
    ``,
    `Não quer mais? Cancele num clique: ${opts.unsubUrl}`,
    ``,
    `— Fracta`,
  ].join('\n')

  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const html = `<!doctype html><html><body style="margin:0;background:#f4f5f7;padding:24px 0">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="text-align:center">
<table role="presentation" align="center" width="600" cellpadding="0" cellspacing="0" style="margin:0 auto;width:600px;max-width:600px;text-align:left;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e6e8eb">
  <tr><td style="padding:0;line-height:0">
    <img src="${esc(opts.headerSrc)}" width="600" alt="Fracta — monitoramento contínuo" style="display:block;width:100%;max-width:600px;height:auto;border:0">
  </td></tr>
  <tr><td style="padding:28px 32px;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#111">
    <p style="font-size:18px;margin:0 0 14px;font-weight:600">Pronto — o Fracta está de olho em <span style="font-family:ui-monospace,Menlo,monospace;color:${CY}">${esc(host)}</span>.</p>
    <p style="font-size:15px;line-height:1.65;color:#3a3f45;margin:0 0 14px">A partir de agora, a gente re-escaneia esse site periodicamente e te avisa por e-mail <strong>se a segurança piorar</strong> — a nota cair ou surgir um problema novo. Nada de spam: só quando algo <strong>realmente muda pra pior</strong>.</p>
    <p style="font-size:14px;line-height:1.6;color:#6b7178;margin:0 0 20px">Determinístico, sem palpite de IA — o mesmo motor do <a href="https://fracta.pro" style="color:${CY};text-decoration:none">fracta.pro</a>.</p>
    <p style="margin:0 0 4px"><a href="https://fracta.pro" style="display:inline-block;background:#0a0b0d;color:#3ad6cf;font-family:ui-monospace,Menlo,monospace;font-size:14px;text-decoration:none;padding:11px 18px;border-radius:8px">❯ analisar outro site</a></p>
  </td></tr>
  <tr><td style="padding:16px 32px 26px;border-top:1px solid #eef0f2;font-family:ui-sans-serif,system-ui,sans-serif">
    <p style="font-size:12px;color:#9aa0a6;margin:0;line-height:1.6">Você pediu para monitorar este site no fracta.pro. Finalidade limitada (só alertas de regressão), sem marketing.<br>
    <a href="${esc(opts.unsubUrl)}" style="color:#9aa0a6">Parar de monitorar / cancelar</a> · <a href="https://fracta.pro/privacidade" style="color:#9aa0a6">Privacidade</a></p>
  </td></tr>
</table>
</td></tr></table></body></html>`

  return { subject, text, html }
}

function safeHost(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}
