import { randomUUID } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory, ScanDepth } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'

const PATH_TEMPLATES = [
  '/users/{id}', '/api/users/{id}', '/api/v1/users/{id}', '/api/v2/users/{id}',
  '/clientes/{id}', '/api/clientes/{id}',
  '/invoices/{id}', '/api/invoices/{id}',
  '/subscriptions/{id}', '/api/subscriptions/{id}',
  '/reports/{id}', '/api/reports/{id}',
  '/documents/{id}', '/api/documents/{id}',
  '/calculos/{id}', '/api/calculos/{id}',
  '/processos/{id}', '/api/processos/{id}',
]

const ENUM_PATHS = ['/api/users/', '/api/clientes/', '/api/calculos/', '/api/processos/']

function getIdsForDepth(depth: ScanDepth): Array<string | number> {
  const base = [1, 2, 999]
  if (depth === 'full') return [...base, 3, 99, 100, 1000]
  if (depth === 'paranoid') return [...base, 3, 99, 100, 1000, '00000000-0000-0000-0000-000000000001']
  return base
}

export class IdorAgent implements SecurityAgent {
  name = 'IDOR Agent'
  category: AgentCategory = 'security'
  concurrency = 2
  timeoutMs = 60_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []

    if (!scope.target.auth) {
      findings.push({
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        severity: 'info',
        title: 'IDOR Agent — autenticação não configurada',
        description: 'Configure auth no targets.yaml para testar IDOR com token de usuário autenticado.',
        recommendation: 'Adicione auth.credentials no targets.yaml para que o IDOR Agent possa obter um token e testar acesso cruzado entre IDs.',
        createdAt: new Date(),
      })
      return findings
    }

    let client: FractaHttpClient
    try {
      const { credentials, endpoint } = scope.target.auth
      if (credentials?.email && credentials?.password && endpoint) {
        const result = await FractaHttpClient.withJwt(
          scope.target.url, endpoint, { email: credentials.email, password: credentials.password }
        )
        client = result.client
      } else {
        client = new FractaHttpClient(scope.target.url)
      }
    } catch {
      client = new FractaHttpClient(scope.target.url)
    }

    const ids = getIdsForDepth(scope.depth)
    const ignore = scope.target.ignore ?? []

    for (const template of PATH_TEMPLATES) {
      for (const id of ids) {
        const path = template.replace('{id}', String(id))
        if (ignore.some(i => path.startsWith(i))) continue

        try {
          const res = await client.request(path, { timeoutMs: 5_000 })

          if (res.status === 200 && res.raw.length > 10) {
            findings.push({
              id: randomUUID(),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              severity: 'critical',
              title: `IDOR — acesso direto por ID: ${path}`,
              description: `${path} retornou HTTP 200 com corpo não-vazio. Possível IDOR — recurso de ID ${id} acessível sem verificar propriedade.`,
              endpoint: path,
              evidence: `GET ${path} → HTTP 200 (${res.raw.length} bytes)\n${res.raw.substring(0, 200)}`,
              recommendation: `Sempre verifique que o recurso pertence ao usuário autenticado:\n\`\`\`typescript\n@Get(':id')\nasync findOne(@Param('id') id: string, @CurrentUser() user: User) {\n  const record = await this.service.findOne(id);\n  if (record.userId !== user.id) throw new ForbiddenException();\n  return record;\n}\n\`\`\``,
              references: [
                'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/',
                'https://cwe.mitre.org/data/definitions/639.html',
              ],
              createdAt: new Date(),
            })
          } else if (res.status === 500) {
            findings.push({
              id: randomUUID(),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              severity: 'medium',
              title: `Erro 500 ao acessar ID inexistente: ${path}`,
              description: `${path} retornou HTTP 500 para ID ${id}, indicando falta de tratamento de erro para recursos não encontrados.`,
              endpoint: path,
              evidence: `GET ${path} (id=${id}) → HTTP 500`,
              recommendation: `Trate recursos não encontrados com 404:\n\`\`\`typescript\nif (!record) throw new NotFoundException(\`Recurso ${id} não encontrado\`);\n\`\`\``,
              references: ['https://owasp.org/www-project-web-security-testing-guide/'],
              createdAt: new Date(),
            })
          }
        } catch { /* timeout — endpoint não existe */ }
      }
    }

    await this.testEnumeration(scope, client, findings, ignore)

    return findings
  }

  private async testEnumeration(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    for (const basePath of ENUM_PATHS) {
      if (ignore.some(i => basePath.startsWith(i))) continue
      let hits = 0

      for (let id = 1; id <= 5; id++) {
        try {
          const res = await client.request(`${basePath}${id}`, { timeoutMs: 4_000 })
          if (res.status === 200 && res.raw.length > 10) hits++
        } catch { /* ignora */ }
      }

      if (hits >= 3) {
        findings.push({
          id: randomUUID(),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          severity: 'high',
          title: `IDs sequenciais enumeráveis: ${basePath}`,
          description: `${hits}/5 IDs sequenciais em ${basePath} retornaram recursos válidos. IDs numéricos previsíveis facilitam enumeração de dados.`,
          endpoint: basePath,
          evidence: `${basePath}1 → 200, ${basePath}2 → 200, ... (${hits}/5 encontrados)`,
          recommendation: 'Use UUIDs em vez de IDs sequenciais:\n```typescript\n@PrimaryGeneratedColumn(\'uuid\')\nid: string;\n```',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'],
          createdAt: new Date(),
        })
      }
    }
  }
}
