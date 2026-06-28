import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { FractaHttpClient, SkippedCheck, stableFindingId } from '@fracta/core'

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
    validate: v => v === 'nosniff',
    message: 'X-Content-Type-Options ausente ou incorreto',
  },
  {
    name: 'x-frame-options',
    severity: 'medium',
    validate: v => v === 'DENY' || v === 'SAMEORIGIN',
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

const FORBIDDEN_HEADERS: Array<{ name: string; severity: Finding['severity']; message: string }> = [
  { name: 'x-powered-by', severity: 'low', message: 'X-Powered-By expõe o framework/versão' },
  { name: 'server', severity: 'low', message: 'Server header expõe informações do servidor web' },
]

export class HeadersAgent implements SecurityAgent {
  name = 'HEADERS Agent'
  category: AgentCategory = 'security'
  concurrency = 1
  timeoutMs = 15_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target } = scope
    const client = new FractaHttpClient(target.url)

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
          `Adicione o header ${rule.name} nas respostas HTTP. Exemplo NestJS:\n\`\`\`typescript\napp.use(helmet()); // inclui ${rule.name} automaticamente\n\`\`\``,
        ))
      }
    }

    for (const rule of FORBIDDEN_HEADERS) {
      if (headers[rule.name]) {
        findings.push(mk(
          `header-forbidden:${rule.name}`,
          rule.severity,
          `Header proibido presente: ${rule.name}`,
          rule.message,
          `Remova o header ${rule.name}. Exemplo NestJS:\n\`\`\`typescript\napp.use(helmet({ ${rule.name === 'x-powered-by' ? 'hidePoweredBy: true' : 'serverInfo: false'} }));\n\`\`\``,
          { evidence: `${rule.name}: ${headers[rule.name]}` },
        ))
      }
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
