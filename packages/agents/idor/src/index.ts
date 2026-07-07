import type { SecurityAgent, ScanScope, Finding, AgentCategory, ScanDepth } from '@fracta/core'
import { FractaHttpClient, stableFindingId } from '@fracta/core'
import { evaluateCrossTenant, type CrossTenantProbe } from './cross-tenant.js'

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
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'idor-auth-not-configured' }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
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
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-direct-access:${path}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
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
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-error-500:${path}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
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
    await this.testCrossTenant(scope, findings)

    return findings
  }

  /**
   * IDOR cross-tenant REAL (2 contas): autentica A e B, confirma que B acessa os
   * próprios recursos e tenta acessá-los como A. A conseguir = vazamento cross-tenant
   * PROVADO (não heurística). Opt-in via `crossTenant` no targets.yaml; read-only.
   */
  private async testCrossTenant(scope: ScanScope, findings: Finding[]): Promise<void> {
    const ct = scope.target.crossTenant
    if (!ct) return

    const auth = scope.target.auth
    const aEndpoint = auth?.endpoint
    const aCreds = auth?.credentials
    if (!aCreds?.email || !aCreds.password || !aEndpoint) {
      findings.push(this.crossTenantInfo(scope,
        'IDOR cross-tenant: requer o tenant A autenticado',
        'O bloco `crossTenant` (tenant B) está configurado, mas falta `auth` com `credentials` (email/senha) e `endpoint` do tenant A. O teste cross-tenant precisa das DUAS identidades.'))
      return
    }

    let clientA: FractaHttpClient
    let clientB: FractaHttpClient
    try {
      clientA = (await FractaHttpClient.withJwt(scope.target.url, aEndpoint, { email: aCreds.email, password: aCreds.password })).client
      clientB = (await FractaHttpClient.withJwt(scope.target.url, ct.endpoint ?? aEndpoint, ct.credentials)).client
    } catch (e) {
      findings.push(this.crossTenantInfo(scope,
        'IDOR cross-tenant: inconclusivo (falha ao autenticar A ou B)',
        `Não foi possível obter token de um dos tenants: ${e instanceof Error ? e.message : String(e)}. Confira credenciais/endpoint.`))
      return
    }

    const probes: CrossTenantProbe[] = []
    for (const resource of ct.ownedResources) {
      let tenantBStatus = 0
      let tenantAStatus = 0
      let tenantABytes = 0
      let tenantABody: string | undefined
      try { tenantBStatus = (await clientB.request(resource, { timeoutMs: 5_000 })).status } catch { /* B inacessível */ }
      try {
        const ra = await clientA.request(resource, { timeoutMs: 5_000 })
        tenantAStatus = ra.status; tenantABytes = ra.raw.length; tenantABody = ra.raw
      } catch { /* A negado/timeout */ }
      probes.push({ resource, tenantBStatus, tenantAStatus, tenantABytes, tenantABody })
    }

    findings.push(...evaluateCrossTenant({ saas: scope.target.name, runId: scope.runId, probes }))
  }

  private crossTenantInfo(scope: ScanScope, title: string, description: string): Finding {
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-crosstenant-setup:${title}` }),
      runId: scope.runId, agent: this.name, category: this.category, camada: this.category,
      severity: 'info', confidence: 'high', title, description,
      recommendation: 'Configure `auth` (tenant A) + `crossTenant` (tenant B, com `ownedResources`) no targets.yaml para provar isolamento multi-tenant.',
      createdAt: new Date(),
    }
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
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-enumeration:${basePath}`, location: basePath }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
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
