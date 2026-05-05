import { randomUUID } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'

const COMMON_ENDPOINTS = [
  '/api/users', '/api/admin', '/api/dashboard', '/api/reports',
  '/api/clientes', '/api/calculos', '/api/processos', '/api/invoices',
  '/api/subscriptions', '/api/billing', '/admin', '/api/v1/users',
  '/api/v2/users', '/api/me', '/api/profile',
]

function makeAlgNoneJwt(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({ role: 'ADMIN', sub: '1', iat: Math.floor(Date.now() / 1000) })).toString('base64url')
  return `${header}.${payload}.`
}

const MALFORMED_TOKENS = [
  'invalid.token.here',
  makeAlgNoneJwt(),
  'Bearer null',
  'Bearer undefined',
  'Bearer ',
  'null',
  '',
]

export class AuthAgent implements SecurityAgent {
  name = 'AUTH Agent'
  category: AgentCategory = 'security'
  concurrency = 2
  timeoutMs = 30_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const client = new FractaHttpClient(scope.target.url)

    await this.testUnauthenticatedAccess(scope, client, findings)
    await this.testMalformedTokens(scope, client, findings)
    await this.testRateLimit(scope, findings)

    return findings
  }

  private async testUnauthenticatedAccess(
    scope: ScanScope, client: FractaHttpClient, findings: Finding[]
  ): Promise<void> {
    const ignore = scope.target.ignore ?? []

    for (const endpoint of COMMON_ENDPOINTS) {
      if (ignore.some(i => endpoint.startsWith(i))) continue
      try {
        const res = await client.request(endpoint, { timeoutMs: 5_000 })
        if (res.status === 200 && res.raw.length > 10) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'critical',
            title: `Endpoint desprotegido: ${endpoint}`,
            description: `${endpoint} retornou HTTP 200 sem autenticação, expondo dados potencialmente sensíveis.`,
            endpoint,
            evidence: `GET ${endpoint} → HTTP 200 (${res.raw.length} bytes)`,
            recommendation: `Adicione guard de autenticação no endpoint:\n\`\`\`typescript\n@UseGuards(JwtAuthGuard)\n@Get('${endpoint.replace('/api/', '')}')\nasync findAll() { ... }\n\`\`\``,
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'],
            createdAt: new Date(),
          })
        }
      } catch { /* timeout ou connection refused — endpoint não existe */ }
    }
  }

  private async testMalformedTokens(
    scope: ScanScope, client: FractaHttpClient, findings: Finding[]
  ): Promise<void> {
    const testEndpoints = COMMON_ENDPOINTS.slice(0, 5)
    const ignore = scope.target.ignore ?? []

    for (const endpoint of testEndpoints) {
      if (ignore.some(i => endpoint.startsWith(i))) continue
      for (const token of MALFORMED_TOKENS) {
        try {
          const res = await client.request(endpoint, {
            headers: { Authorization: token },
            timeoutMs: 5_000,
          })
          if (res.status === 200 && res.raw.length > 10) {
            findings.push({
              id: randomUUID(),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              severity: 'critical',
              title: `Token malformado aceito: ${endpoint}`,
              description: `${endpoint} retornou HTTP 200 com token inválido "${token.substring(0, 30)}..."`,
              endpoint,
              evidence: `Authorization: ${token.substring(0, 50)}\n→ HTTP 200`,
              recommendation: 'Valide tokens JWT com biblioteca robusta e rejeite tokens com alg:none:\n```typescript\nJwtModule.register({ secret: process.env.JWT_SECRET, signOptions: { algorithm: \'HS256\' } })\n```',
              references: [
                'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/',
                'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235',
              ],
              createdAt: new Date(),
            })
            break
          }
        } catch { /* ignora */ }
      }
    }
  }

  private async testRateLimit(scope: ScanScope, findings: Finding[]): Promise<void> {
    const authEndpoint = scope.target.auth?.endpoint
    if (!authEndpoint) {
      findings.push({
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        severity: 'info',
        title: 'Rate limit não testado — auth.endpoint não configurado',
        description: 'Configure auth.endpoint no targets.yaml para testar proteção contra brute force.',
        recommendation: 'Adicione auth.endpoint no targets.yaml:\n```yaml\nauth:\n  endpoint: /api/auth/login\n```',
        createdAt: new Date(),
      })
      return
    }

    const client = new FractaHttpClient(scope.target.url)
    const body = { email: 'brute@fracta.test', password: 'wrong-password-fracta-12345' }

    const requests = Array.from({ length: 10 }, () =>
      client.request(authEndpoint, { method: 'POST', body, timeoutMs: 5_000 }).catch(() => null)
    )

    const results = await Promise.all(requests)
    const rateLimited = results.filter(r => r?.status === 429).length

    if (rateLimited < 2) {
      findings.push({
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        severity: 'high',
        title: 'Rate limiting ausente no endpoint de login',
        description: `10 requisições simultâneas de login inválido retornaram apenas ${rateLimited} respostas 429. Proteção contra brute force insuficiente.`,
        endpoint: authEndpoint,
        evidence: `10 POST ${authEndpoint} com credenciais erradas → ${rateLimited}/10 retornaram 429`,
        recommendation: 'Implemente rate limiting no endpoint de login:\n```typescript\nimport { ThrottlerGuard } from \'@nestjs/throttler\';\n\n@UseGuards(ThrottlerGuard)\n@Post(\'login\')\nasync login(@Body() dto: LoginDto) { ... }\n```',
        references: ['https://owasp.org/www-community/attacks/Brute_force_attack'],
        createdAt: new Date(),
      })
    }
  }
}
