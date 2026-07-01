import type { SecurityAgent, ScanScope, Finding, AgentCategory, StackType } from '@fracta/core'
import { FractaHttpClient, SkippedCheck, stableFindingId } from '@fracta/core'
import { analyzeCsp } from './csp.js'

/**
 * O fetch junta headers repetidos numa única string separada por vírgula
 * (ex.: helmet + nginx emitindo `x-content-type-options: nosniff` resultam em
 * "nosniff, nosniff"). Quebra em tokens para validar valor-a-valor — assim um
 * header duplicado idêntico é aceito, mas um valor conflitante ainda é flagrado.
 */
const tokens = (v: string): string[] => v.split(',').map(s => s.trim()).filter(Boolean)

/**
 * CDN/hosting providers that set the `server` header automatically.
 * The user cannot remove these at the origin — must inform them instead.
 */
const KNOWN_CDN_SERVERS = ['cloudflare', 'vercel', 'fastly', 'akamai', 'netlify', 'awselb', 'amazon', 'nginx/']

function isKnownCdn(serverValue: string): boolean {
  const lower = serverValue.toLowerCase()
  return KNOWN_CDN_SERVERS.some(cdn => lower.includes(cdn))
}

/**
 * O risco real de um header `server`/`x-powered-by` é o disclosure de VERSÃO
 * (facilita fingerprinting de CVEs). Um `server` SEM versão (`cloudflare`, `vercel`,
 * `nginx` puro com server_tokens off) é apenas informativo e não-acionável — definido
 * por CDN/proxy, não removível na origem. `name/1.2` → tem versão. Vendor-agnóstico.
 */
function hasVersionToken(value: string): boolean {
  return /\/\s*\d/.test(value)
}

/**
 * Returns a stack-aware fix snippet for a required security header.
 *
 * - nestjs / nodejs / express → helmet() example (noting what helmet covers and what it doesn't)
 * - nextjs → next.config.js `async headers()` example
 * - unknown/empty → neutral "configure seu servidor" guidance
 */
function requiredHeaderRec(headerName: string, stack: StackType[]): string {
  const has = (s: string) => stack.some(t => t.toLowerCase() === s)

  if (has('nextjs')) {
    return (
      `Adicione o header \`${headerName}\` via \`next.config.js\`:\n` +
      `\`\`\`js\n` +
      `// next.config.js\n` +
      `module.exports = {\n` +
      `  async headers() {\n` +
      `    return [{ source: '/(.*)', headers: [{ key: '${headerName}', value: '<valor recomendado>' }] }]\n` +
      `  },\n` +
      `}\n` +
      `\`\`\``
    )
  }

  if (has('nestjs') || has('nodejs') || has('express')) {
    // helmet sets: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy automatically.
    // Permissions-Policy is NOT set by helmet by default — must be configured explicitly.
    if (headerName === 'permissions-policy') {
      return (
        `Adicione o header \`permissions-policy\` explicitamente — helmet **não** o define por padrão:\n` +
        `\`\`\`typescript\n` +
        `app.use(helmet());\n` +
        `app.use((_req, res, next) => {\n` +
        `  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');\n` +
        `  next();\n` +
        `});\n` +
        `\`\`\``
      )
    }
    return (
      `Adicione o header \`${headerName}\` via helmet:\n` +
      `\`\`\`typescript\n` +
      `app.use(helmet()); // inclui ${headerName} automaticamente\n` +
      `\`\`\``
    )
  }

  // Neutral — unknown/empty stack
  return `Configure seu servidor/proxy para enviar o header \`${headerName}\` com o valor recomendado pela OWASP Secure Headers Project.`
}

/**
 * Returns a stack-aware recommendation for the `x-powered-by` forbidden header.
 */
function xPoweredByRec(stack: StackType[]): string {
  const has = (s: string) => stack.some(t => t.toLowerCase() === s)

  if (has('nextjs')) {
    return (
      `Desative o \`X-Powered-By\` em \`next.config.js\`:\n` +
      `\`\`\`js\n` +
      `// next.config.js\n` +
      `module.exports = { poweredByHeader: false }\n` +
      `\`\`\``
    )
  }

  if (has('nestjs') || has('nodejs') || has('express')) {
    return (
      `Desative o \`X-Powered-By\` no Express/NestJS:\n` +
      `\`\`\`typescript\n` +
      `app.disable('x-powered-by');\n` +
      `\`\`\``
    )
  }

  return `Configure seu servidor/proxy para omitir o header \`X-Powered-By\` nas respostas HTTP.`
}

/**
 * Returns a recommendation for the `server` forbidden header.
 * If the value identifies a CDN, explains the user cannot remove it at origin.
 */
function serverHeaderRec(serverValue: string, stack: StackType[]): string {
  if (isKnownCdn(serverValue)) {
    return (
      `O valor \`${serverValue}\` é definido pelo CDN/hosting provider e **não pode ser removido na origem**. ` +
      `É controlado pela infraestrutura (Cloudflare, Vercel, etc.). ` +
      `Considere configurar regras de transformação de headers no painel do seu CDN para ocultar ou substituir o valor, se necessário.`
    )
  }

  const has = (s: string) => stack.some(t => t.toLowerCase() === s)

  if (has('nestjs') || has('nodejs') || has('express')) {
    return (
      `O header \`server\` é definido pelo servidor web/proxy (nginx, Apache), não pelo Node.js. ` +
      `Para ocultar a versão no nginx use \`server_tokens off;\` em \`nginx.conf\`. ` +
      `Para remoção completa do header instale o módulo \`headers-more-nginx-module\` e use \`more_clear_headers Server;\`.`
    )
  }

  if (has('nextjs')) {
    return (
      `O header \`server\` é definido pelo servidor web/proxy (nginx, Apache ou o servidor Next.js). ` +
      `Para ocultar a versão no nginx use \`server_tokens off;\` em \`nginx.conf\`. ` +
      `Para remoção completa instale \`headers-more-nginx-module\` e use \`more_clear_headers Server;\`.`
    )
  }

  return (
    `O header \`server\` é definido pelo servidor web/proxy (nginx, Apache, etc.), não pela aplicação. ` +
    `Para ocultar a versão no nginx use \`server_tokens off;\` em \`nginx.conf\`. ` +
    `Para remoção completa instale \`headers-more-nginx-module\` e use \`more_clear_headers Server;\`.`
  )
}

const REQUIRED_HEADERS: Array<{
  name: string
  severity: Finding['severity']
  validate: (value: string) => boolean
  message: string
}> = [
  {
    name: 'strict-transport-security',
    severity: 'high',
    validate: v => v.includes('max-age='),
    message: 'HSTS ausente ou sem max-age',
  },
  {
    name: 'x-content-type-options',
    severity: 'medium',
    validate: v => { const t = tokens(v); return t.length > 0 && t.every(x => x.toLowerCase() === 'nosniff') },
    message: 'X-Content-Type-Options ausente ou incorreto',
  },
  {
    name: 'x-frame-options',
    severity: 'medium',
    validate: v => { const t = tokens(v); return t.length > 0 && t.every(x => x.toUpperCase() === 'DENY' || x.toUpperCase() === 'SAMEORIGIN') },
    message: 'X-Frame-Options ausente ou incorreto',
  },
  {
    name: 'referrer-policy',
    severity: 'low',
    validate: v => v.length > 0,
    message: 'Referrer-Policy ausente',
  },
  {
    name: 'permissions-policy',
    severity: 'low',
    validate: v => v.length > 0,
    message: 'Permissions-Policy ausente',
  },
]

export class HeadersAgent implements SecurityAgent {
  name = 'HEADERS Agent'
  category: AgentCategory = 'security'
  concurrency = 1
  timeoutMs = 15_000

  /**
   * `createClient` permite injetar um cliente HTTP endurecido (ex.: o
   * `@fracta/web-scan` injeta um cliente com dispatcher que valida o IP em
   * cada conexão, fechando SSRF por redirect). Sem ele, usa o cliente padrão
   * (comportamento histórico do CLI).
   */
  constructor(private readonly opts: { createClient?: (url: string) => FractaHttpClient } = {}) {}

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target } = scope
    const client = this.opts.createClient?.(target.url) ?? new FractaHttpClient(target.url)

    let res
    try {
      res = await client.request('/', { timeoutMs: this.timeoutMs })
    } catch (err) {
      // Alvo inacessível não é "seguro" nem é erro do check — é não-verificado.
      throw new SkippedCheck(`não foi possível conectar a ${target.url}: ${String(err)}`)
    }

    const headers = res.headers

    const mk = (
      rule: string,
      severity: Finding['severity'],
      title: string,
      description: string,
      recommendation: string,
      extra: Partial<Finding> = {},
    ): Finding => ({
      id: stableFindingId({ saas: target.name, camada: this.category, rule, location: target.url }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity,
      title,
      description,
      recommendation,
      references: ['https://owasp.org/www-project-secure-headers/'],
      createdAt: new Date(),
      ...extra,
    })

    for (const rule of REQUIRED_HEADERS) {
      const value = headers[rule.name] ?? ''
      if (!value || !rule.validate(value)) {
        findings.push(mk(
          `header-missing:${rule.name}`,
          rule.severity,
          `Security header ausente: ${rule.name}`,
          rule.message,
          requiredHeaderRec(rule.name, target.stack ?? []),
        ))
      }
    }

    // ── Content-Security-Policy: análise PROFUNDA (parseia a policy, não só presença) ──
    const csp = (headers['content-security-policy'] ?? '').trim()
    const cspReportOnly = (headers['content-security-policy-report-only'] ?? '').trim()
    if (!csp && !cspReportOnly) {
      // Ausência = defesa-em-profundidade faltando → low (não é um buraco direto).
      findings.push(mk(
        'csp-missing', 'low',
        'Content-Security-Policy ausente',
        'Sem CSP, o navegador não tem uma política para bloquear scripts/recursos injetados — é a defesa mais forte contra XSS. Ausência não é um buraco direto, mas é a camada que mais reduz o impacto de um XSS.',
        "Adicione um CSP. Comece em Report-Only para não quebrar, com baseline: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'. Em Next.js, use nonce por request.",
        { confidence: 'high', proposedFix: {
          description: "Baseline (endureça conforme o app):  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none' . Suba primeiro como Content-Security-Policy-Report-Only para observar violações sem quebrar, depois troque para enforcement.",
          riskOfApplying: 'PROPOSTA — um CSP estrito pode quebrar scripts/estilos inline legítimos. Por isso: Report-Only primeiro, ajuste, e só então imponha. Em Next.js use nonce (senão a hidratação quebra).',
        } },
      ))
    } else if (!csp && cspReportOnly) {
      findings.push(mk(
        'csp-report-only', 'low',
        'CSP presente apenas em Report-Only (não bloqueia)',
        'Há um Content-Security-Policy-Report-Only, mas nenhum CSP em modo de imposição. Report-Only só coleta violações — NÃO bloqueia scripts injetados.',
        'Depois de validar as violações do Report-Only, publique a mesma policy como Content-Security-Policy (enforcement).',
        { confidence: 'high' },
      ))
    } else {
      for (const issue of analyzeCsp(csp)) {
        findings.push(mk(
          issue.rule, issue.severity, issue.title, issue.detail, issue.recommendation,
          { confidence: 'high', evidence: `content-security-policy: ${csp.length > 220 ? csp.slice(0, 220) + '…' : csp}` },
        ))
      }
    }

    // x-powered-by: vaza framework/versão → sempre low.
    if (headers['x-powered-by']) {
      const v = headers['x-powered-by'] as string
      findings.push(mk(
        'header-forbidden:x-powered-by',
        'low',
        'Header proibido presente: x-powered-by',
        'X-Powered-By expõe o framework/versão',
        xPoweredByRec(target.stack ?? []),
        { evidence: `x-powered-by: ${v}` },
      ))
    }

    // server: VERSÃO exposta (nginx/1.24.0, Apache/2.4.1) = risco de fingerprinting → low.
    // Sem versão (cloudflare, vercel, nginx puro) = informativo e não-acionável (CDN/proxy,
    // não removível na origem) → info (0 pontos): mostramos p/ transparência, mas não
    // descontamos nota por algo que o próprio relatório admite ser incontrolável.
    if (headers['server']) {
      const v = headers['server'] as string
      const versioned = hasVersionToken(v)
      findings.push(mk(
        'header-forbidden:server',
        versioned ? 'low' : 'info',
        versioned ? 'Server header expõe a versão do servidor: server' : 'Server header presente (informativo): server',
        versioned
          ? 'O header `server` revela a versão do servidor web (facilita fingerprinting de vulnerabilidades conhecidas).'
          : 'Header `server` presente, sem versão exposta — informativo e não-acionável (definido por CDN/proxy, não removível na origem).',
        serverHeaderRec(v, target.stack ?? []),
        { evidence: `server: ${v}` },
      ))
    }

    await this.testCors(scope, client, findings, mk)

    return findings
  }

  private async testCors(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    mk: (
      rule: string,
      severity: Finding['severity'],
      title: string,
      description: string,
      recommendation: string,
      extra?: Partial<Finding>,
    ) => Finding,
  ): Promise<void> {
    const origins = ['https://evil.com', 'null']

    for (const origin of origins) {
      try {
        const res = await client.request('/', {
          headers: { Origin: origin },
          timeoutMs: 5_000,
        })

        const acao = res.headers['access-control-allow-origin'] ?? ''

        if (acao === '*') {
          findings.push(mk(
            'cors-wildcard',
            'high',
            'CORS wildcard: Access-Control-Allow-Origin: *',
            'O servidor aceita requisições cross-origin de qualquer origem.',
            'Configure CORS para aceitar apenas origens conhecidas:\n```typescript\napp.enableCors({ origin: [\'https://meuapp.com.br\'] });\n```',
            {
              evidence: `Origin: ${origin} → Access-Control-Allow-Origin: *`,
              references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
            },
          ))
          break // wildcard é estável independente da origem testada
        } else if (acao === origin && origin !== 'null') {
          findings.push(mk(
            'cors-reflect',
            'medium',
            'CORS reflete origem arbitrária',
            'O servidor reflete qualquer origem recebida no Access-Control-Allow-Origin.',
            'Use uma allowlist explícita de origens no CORS config.',
            {
              evidence: `Origin: ${origin} → Access-Control-Allow-Origin: ${acao}`,
              references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
            },
          ))
        }
      } catch { /* timeout ou rede — ignora esta origem */ }
    }
  }
}
