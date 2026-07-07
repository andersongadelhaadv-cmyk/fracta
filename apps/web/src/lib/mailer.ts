import 'server-only'

export interface OutboundEmail {
  subject: string
  text: string
  html: string
}

/**
 * Envia um e-mail transacional via Resend (fetch direto, sem SDK). Lança se não
 * configurado — só é chamado quando o monitor NÃO está em dry-run. Remetente e chave
 * vêm do ambiente (`.env` da VPS): `RESEND_API_KEY` e `MONITOR_FROM`.
 */
export async function sendEmail(to: string, email: OutboundEmail): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY
  const from = process.env.MONITOR_FROM
  if (!apiKey || !from) {
    throw new Error('Envio desativado: RESEND_API_KEY/MONITOR_FROM não configurados.')
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ from, to, subject: email.subject, text: email.text, html: email.html }),
  })
  if (!res.ok) {
    throw new Error(`Resend respondeu ${res.status}: ${await res.text().catch(() => '')}`)
  }
}
