import { randomUUID } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'

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
    const client = new FractaHttpClient(scope.target.url)

    try {
      const res = await client.request('/', { timeoutMs: this.timeoutMs })
      const headers = res.headers

      for (const rule of REQUIRED_HEADERS) {
        const value = headers[rule.name] ?? ''
        if (!value || !rule.validate(value)) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: rule.severity,
            title: `Security header ausente: ${rule.name}`,
            description: rule.message,
            recommendation: `Adicione o header ${rule.name} nas respostas HTTP. Exemplo NestJS:\n\`\`\`typescript\napp.use(helmet()); // inclui ${rule.name} automaticamente\n\`\`\``,
            references: ['https://owasp.org/www-project-secure-headers/'],
            createdAt: new Date(),
          })
        }
      }

      for (const rule of FORBIDDEN_HEADERS) {
        if (headers[rule.name]) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: rule.severity,
            title: `Header proibido presente: ${rule.name}`,
            description: rule.message,
            evidence: `${rule.name}: ${headers[rule.name]}`,
            recommendation: `Remova o header ${rule.name}. Exemplo NestJS:\n\`\`\`typescript\napp.use(helmet({ ${rule.name === 'x-powered-by' ? 'hidePoweredBy: true' : 'serverInfo: false'} }));\n\`\`\``,
            references: ['https://owasp.org/www-project-secure-headers/'],
            createdAt: new Date(),
          })
        }
      }

      await this.testCors(scope, client, findings)
    } catch (err) {
      findings.push({
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        severity: 'info',
        title: 'HEADERS Agent — erro de conexão',
        description: `Não foi possível conectar a ${scope.target.url}: ${String(err)}`,
        recommendation: 'Verifique se o target está acessível e a URL está correta.',
        createdAt: new Date(),
      })
    }

    return findings
  }

  private async testCors(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[]
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
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'high',
            title: 'CORS wildcard: Access-Control-Allow-Origin: *',
            description: 'O servidor aceita requisições cross-origin de qualquer origem.',
            evidence: `Origin: ${origin} → Access-Control-Allow-Origin: *`,
            recommendation: 'Configure CORS para aceitar apenas origens conhecidas:\n```typescript\napp.enableCors({ origin: [\'https://meuapp.com.br\'] });\n```',
            references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
            createdAt: new Date(),
          })
        } else if (acao === origin && origin !== 'null') {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'medium',
            title: 'CORS reflete origem arbitrária',
            description: 'O servidor reflete qualquer origem recebida no Access-Control-Allow-Origin.',
            evidence: `Origin: ${origin} → Access-Control-Allow-Origin: ${acao}`,
            recommendation: 'Use uma allowlist explícita de origens no CORS config.',
            references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
            createdAt: new Date(),
          })
        }
      } catch { /* timeout ou rede — ignora */ }
    }
  }
}
