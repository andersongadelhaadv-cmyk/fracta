import type { Finding } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

/** Analisa headers Set-Cookie (passivo). Cookie sem Secure/HttpOnly/SameSite → finding low. */
export function findCookieIssues(setCookies: string[], saas: string, runId: string): Finding[] {
  const out: Finding[] = []
  for (const raw of setCookies) {
    const name = raw.split('=')[0]?.trim() ?? '(sem nome)'
    // Atributos vêm após o 1º ';'. Parse por atributo evita falso-negativo quando
    // o VALOR do cookie contém a palavra "secure" (ex.: session=secure-token).
    const attrs = raw.split(';').slice(1).map((s) => s.trim().toLowerCase())
    const has = (attr: string) => attrs.some((a) => a === attr || a.startsWith(`${attr}=`))
    const missing: string[] = []
    if (!has('secure')) missing.push('Secure')
    if (!has('httponly')) missing.push('HttpOnly')
    if (!has('samesite')) missing.push('SameSite')
    if (missing.length === 0) continue
    out.push({
      id: stableFindingId({ saas, camada: 'security', rule: `cookie-flags:${name}`, location: name }),
      runId,
      agent: 'COOKIE Check',
      category: 'security',
      camada: 'security',
      severity: 'low',
      title: `Cookie sem flags de segurança: ${name}`,
      description: `O cookie "${name}" não define: ${missing.join(', ')}. Sem essas flags ele é mais exposto a roubo (XSS) e envio cross-site (CSRF).`,
      evidence: `Set-Cookie: ${name}=… (faltam: ${missing.join(', ')})`,
      recommendation: 'Defina Secure, HttpOnly e SameSite (Lax/Strict) nos cookies de sessão.',
      proposedFix: {
        description:
          `Recrie o cookie "${name}" com as flags que faltam. No header:  Set-Cookie: ${name}=<valor>; Secure; HttpOnly; SameSite=Lax; Path=/ .  ` +
          `Express:  res.cookie('${name}', v, { secure: true, httpOnly: true, sameSite: 'lax' }) .  ` +
          `Next.js (route handler):  cookies().set('${name}', v, { secure: true, httpOnly: true, sameSite: 'lax', path: '/' }) .`,
        riskOfApplying:
          'PROPOSTA — não aplicada. HttpOnly impede leitura via JS (correto p/ cookie de sessão; quebra só se algum front lê esse cookie por JS). SameSite=Strict pode quebrar login via redirect cross-site — use Lax nesses casos.',
      },
      references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
      createdAt: new Date(),
    })
  }
  return out
}
