import { randomUUID } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'

const SWAGGER_PATHS = [
  '/api', '/api/docs', '/api/swagger', '/api-docs', '/api-json',
  '/docs', '/swagger', '/swagger-ui', '/swagger.json', '/openapi.json',
]

const HEALTH_PATHS = ['/health', '/healthz', '/api/health', '/api/healthz', '/api/__healthcheck']

const HEALTH_LEAK_PATTERNS: RegExp[] = [
  /\b(NODE_ENV|DATABASE_URL|REDIS_URL|JWT_SECRET|STRIPE_|SUPABASE_)/i,
  /password\s*[:=]/i,
  /\b(home|usr|src)\/[\w/.-]+\/node_modules\b/,
  /\bcom\.amazonaws\b/i,
]

function looksLikeSwagger(body: string): boolean {
  const lower = body.substring(0, 4000).toLowerCase()
  return (
    lower.includes('swagger') ||
    lower.includes('openapi') ||
    lower.includes('redoc') ||
    (lower.includes('"paths"') && lower.includes('"info"'))
  )
}

export class NestJSSkill implements SecurityAgent {
  name = 'NestJS Skill'
  category: AgentCategory = 'security'
  concurrency = 2
  timeoutMs = 60_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target } = scope

    if (!target.stack.includes('nestjs')) return findings

    const client = new FractaHttpClient(target.url)
    const ignore = target.ignore ?? []

    await this.probeSwagger(scope, client, findings, ignore)
    await this.probeHealth(scope, client, findings, ignore)

    return findings
  }

  private async probeSwagger(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    for (const path of SWAGGER_PATHS) {
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await client.request(path, { timeoutMs: 4_000 })
        if (res.status === 200 && looksLikeSwagger(res.raw)) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'high',
            title: `Swagger/OpenAPI exposto: ${path}`,
            description: `${path} retornou conteúdo de documentação Swagger/OpenAPI. Em produção, isso vaza estrutura completa da API (rotas, params, schemas) e facilita enumeração de endpoints para um atacante.`,
            endpoint: path,
            evidence: `GET ${path} → HTTP 200 (${res.raw.length} bytes)\n${res.raw.substring(0, 200).replace(/\s+/g, ' ').trim()}`,
            recommendation: 'Desative Swagger em produção:\n```typescript\nif (process.env.NODE_ENV !== \'production\') {\n  const config = new DocumentBuilder().setTitle(\'API\').build();\n  SwaggerModule.setup(\'api\', app, SwaggerModule.createDocument(app, config));\n}\n```',
            references: [
              'https://docs.nestjs.com/openapi/introduction',
              'https://owasp.org/www-project-api-security/',
            ],
            createdAt: new Date(),
          })
          return
        }
      } catch { /* ignora */ }
    }
  }

  private async probeHealth(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    for (const path of HEALTH_PATHS) {
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await client.request(path, { timeoutMs: 4_000 })
        if (res.status !== 200 || res.raw.length < 10) continue

        const leaked = HEALTH_LEAK_PATTERNS.find(re => re.test(res.raw))
        if (leaked) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'medium',
            title: `Health endpoint vaza informação sensível: ${path}`,
            description: `${path} retornou corpo contendo padrão sensível (${leaked.source}). Health endpoints públicos não devem expor env vars, paths de filesystem ou credenciais.`,
            endpoint: path,
            evidence: `GET ${path} → HTTP 200\n${res.raw.substring(0, 300).replace(/\s+/g, ' ').trim()}`,
            recommendation: 'Use @nestjs/terminus com indicators mínimos (db ping, memory) e nunca inclua env/configs no payload:\n```typescript\n@Get(\'health\')\n@HealthCheck()\ncheck() {\n  return this.health.check([() => this.db.pingCheck(\'database\')]);\n}\n```',
            references: ['https://docs.nestjs.com/recipes/terminus'],
            createdAt: new Date(),
          })
          return
        }
      } catch { /* ignora */ }
    }
  }
}
