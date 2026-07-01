import type { Severity } from '@fracta/core'

export interface CspIssue {
  rule: string
  severity: Severity
  title: string
  detail: string
  recommendation: string
}

/** Parseia a policy em diretiva → valores (lowercase). */
function parse(policy: string): Map<string, string[]> {
  const map = new Map<string, string[]>()
  for (const part of policy.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const [name, ...vals] = trimmed.split(/\s+/)
    if (name) map.set(name.toLowerCase(), vals.map(v => v.toLowerCase()))
  }
  return map
}

/**
 * Análise DETERMINÍSTICA de um Content-Security-Policy (parseia a policy, não só a
 * presença). Confiança alta — é o texto real do header. Prioriza o que ANULA a
 * proteção (unsafe-inline em script = high) sobre o que é só endurecimento (low).
 */
export function analyzeCsp(policy: string): CspIssue[] {
  const d = parse(policy)
  const issues: CspIssue[] = []
  const scriptSrc = d.get('script-src') ?? d.get('default-src')
  const styleSrc = d.get('style-src') ?? d.get('default-src')
  const has = (dir: string) => d.has(dir)

  // 'unsafe-inline' em script-src ANULA a principal proteção do CSP → high.
  if (scriptSrc?.includes("'unsafe-inline'") && !scriptSrc.some(v => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
    issues.push({
      rule: 'csp-unsafe-inline-script', severity: 'high',
      title: "CSP com 'unsafe-inline' em script-src",
      detail: "'unsafe-inline' autoriza QUALQUER script inline — inclusive o injetado por XSS. Isso anula a principal proteção do CSP: o header existe, mas contra XSS não vale quase nada.",
      recommendation: "Remova 'unsafe-inline' de script-src e use nonce por request ou hash dos scripts inline (com 'strict-dynamic').",
    })
  }
  // 'unsafe-eval' → amplia superfície de XSS.
  if (scriptSrc?.includes("'unsafe-eval'")) {
    issues.push({
      rule: 'csp-unsafe-eval', severity: 'medium',
      title: "CSP com 'unsafe-eval' em script-src",
      detail: "'unsafe-eval' reabre eval()/new Function()/setTimeout(string) — amplia a superfície de XSS.",
      recommendation: "Remova 'unsafe-eval' e refatore o código que depende de eval/Function dinâmicos.",
    })
  }
  // Sem script-src nem default-src → scripts irrestritos.
  if (!has('script-src') && !has('default-src')) {
    issues.push({
      rule: 'csp-no-script-src', severity: 'medium',
      title: 'CSP sem script-src nem default-src',
      detail: 'Sem script-src (nem default-src como fallback), a origem dos scripts não é restringida pela policy.',
      recommendation: "Defina script-src 'self' (+ nonce/hash p/ inline) ou ao menos um default-src 'self'.",
    })
  }
  // script-src amplo (* ou https:) → quase qualquer origem.
  if (scriptSrc && (scriptSrc.includes('*') || scriptSrc.includes('https:') || scriptSrc.includes('http:'))) {
    issues.push({
      rule: 'csp-broad-script-src', severity: 'medium',
      title: 'CSP com script-src muito amplo (* / https:)',
      detail: "Permitir '*', 'https:' ou 'http:' em script-src deixa carregar script de quase qualquer origem — enfraquece muito a proteção.",
      recommendation: 'Liste apenas as origens confiáveis; prefira nonce/hash + strict-dynamic a curingas.',
    })
  }
  // Sem default-src → diretivas não declaradas ficam sem fallback.
  if (!has('default-src')) {
    issues.push({
      rule: 'csp-no-default-src', severity: 'low',
      title: 'CSP sem default-src',
      detail: 'Sem default-src, diretivas não declaradas (img-src, connect-src, font-src…) não têm fallback restritivo.',
      recommendation: "Adicione default-src 'self' como base e sobreponha só o necessário.",
    })
  }
  // object-src não travado → vetor legado (<object>/<embed>).
  const objectSrc = d.get('object-src')
  if (!objectSrc || !objectSrc.includes("'none'")) {
    issues.push({
      rule: 'csp-object-src', severity: 'low',
      title: "CSP sem object-src 'none'",
      detail: "object-src 'none' bloqueia <object>/<embed>/<applet> — vetores legados de execução de conteúdo.",
      recommendation: "Adicione object-src 'none'.",
    })
  }
  // base-uri ausente → <base> injetado sequestra URLs relativas.
  if (!has('base-uri')) {
    issues.push({
      rule: 'csp-no-base-uri', severity: 'low',
      title: 'CSP sem base-uri',
      detail: "Sem base-uri 'self', uma tag <base> injetada pode redirecionar todas as URLs relativas (roubo de recursos/scripts).",
      recommendation: "Adicione base-uri 'self'.",
    })
  }
  // 'unsafe-inline' em style-src → menor risco, mas ainda relevante.
  if (styleSrc?.includes("'unsafe-inline'") && !styleSrc.some(v => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
    issues.push({
      rule: 'csp-unsafe-inline-style', severity: 'info',
      title: "CSP com 'unsafe-inline' em style-src",
      detail: 'Menor risco que em scripts, mas permite CSS injetado (UI redress/exfiltração via seletores). Informativo.',
      recommendation: 'Prefira nonce/hash para estilos inline quando viável.',
    })
  }
  return issues
}
