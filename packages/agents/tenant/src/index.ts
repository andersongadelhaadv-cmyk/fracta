import type { SecurityAgent, ScanScope, Finding, AgentCategory, ScanDepth } from '@fracta/core'
import { FractaHttpClient, stableFindingId } from '@fracta/core'

const ADMIN_PATHS = [
  '/api/admin', '/api/admin/users', '/api/admin/tenants',
  '/api/admin/organizations', '/api/admin/dashboard', '/api/admin/stats',
  '/admin', '/admin/users', '/admin/api',
  '/api/_internal', '/api/internal', '/internal',
]

const TENANT_LIST_PATHS = [
  '/api/tenants', '/api/orgs', '/api/organizations', '/api/companies',
  '/api/empresas', '/api/clientes/all', '/api/escritorios',
]

const TENANT_TEMPLATES = [
  '/api/orgs/{id}/users', '/api/orgs/{id}/data',
  '/api/tenants/{id}/users', '/api/tenants/{id}/data',
  '/api/organizations/{id}/members', '/api/organizations/{id}/billing',
  '/api/companies/{id}/employees', '/api/empresas/{id}/dados',
  '/api/escritorios/{id}/clientes',
]

const TENANT_HEADERS = ['X-Tenant-ID', 'X-Tenant', 'X-Org-ID', 'X-Organization-Id', 'X-Company-Id']

function getIdsForDepth(depth: ScanDepth): Array<string | number> {
  const base = [1, 2]
  if (depth === 'full') return [...base, 3, 99]
  if (depth === 'paranoid') return [...base, 3, 99, 1000]
  return base
}

function shortBody(raw: string): string {
  return raw.substring(0, 200).replace(/\s+/g, ' ').trim()
}

export class TenantAgent implements SecurityAgent {
  name = 'TENANT Agent'
  category: AgentCategory = 'security'
  concurrency = 2
  timeoutMs = 90_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target } = scope

    let client: FractaHttpClient
    let authenticated = false

    if (target.auth?.credentials?.email && target.auth?.credentials?.password && target.auth?.endpoint) {
      try {
        const result = await FractaHttpClient.withJwt(
          target.url,
          target.auth.endpoint,
          { email: target.auth.credentials.email, password: target.auth.credentials.password }
        )
        client = result.client
        authenticated = true
      } catch {
        client = new FractaHttpClient(target.url)
      }
    } else {
      client = new FractaHttpClient(target.url)
    }

    if (!authenticated) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'tenant-auth-not-configured' }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'info',
        title: 'TENANT Agent — autenticação não configurada',
        description: 'TENANT Agent testa isolamento entre tenants. Sem credenciais válidas só consegue verificar exposição não-autenticada de rotas admin/tenant.',
        recommendation: 'Configure auth.credentials no targets.yaml para que o TENANT Agent possa testar acesso cruzado com um token autenticado.',
        createdAt: new Date(),
      })
    }

    const ignore = target.ignore ?? []

    await this.probeAdminPaths(scope, client, findings, ignore, authenticated)
    await this.probeTenantPaths(scope, client, findings, ignore)
    if (authenticated) {
      await this.probeHeaderInjection(scope, client, findings, ignore)
    }

    return findings
  }

  private async probeAdminPaths(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[],
    authenticated: boolean
  ): Promise<void> {
    for (const path of [...ADMIN_PATHS, ...TENANT_LIST_PATHS]) {
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await client.request(path, { timeoutMs: 5_000 })
        if (res.status === 200 && res.raw.length > 10) {
          const severity = authenticated ? 'critical' : 'high'
          findings.push({
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `admin-route-exposed:${path}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
            severity,
            title: `Rota administrativa/multi-tenant exposta: ${path}`,
            description: authenticated
              ? `${path} retornou HTTP 200 com um token de usuário comum. Endpoints administrativos não devem ser acessíveis sem checagem de role.`
              : `${path} retornou HTTP 200 sem autenticação. Listagem de tenants/orgs/admin não deveria ser pública.`,
            endpoint: path,
            evidence: `GET ${path} → HTTP 200 (${res.raw.length} bytes)\n${shortBody(res.raw)}`,
            recommendation: 'Proteja rotas administrativas com guard de role e nunca exponha listagens globais de tenants:\n```typescript\n@UseGuards(JwtAuthGuard, RolesGuard)\n@Roles(\'admin\')\n@Get(\'admin/users\')\nlistAll() { ... }\n```',
            references: [
              'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
              'https://cwe.mitre.org/data/definitions/285.html',
            ],
            createdAt: new Date(),
          })
        }
      } catch { /* timeout/connref — endpoint inexistente */ }
    }
  }

  private async probeTenantPaths(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    const ids = getIdsForDepth(scope.depth)

    for (const template of TENANT_TEMPLATES) {
      let hits = 0
      const samples: string[] = []
      for (const id of ids) {
        const path = template.replace('{id}', String(id))
        if (ignore.some(i => path.startsWith(i))) continue
        try {
          const res = await client.request(path, { timeoutMs: 5_000 })
          if (res.status === 200 && res.raw.length > 10) {
            hits++
            samples.push(`${path} → 200 (${res.raw.length} bytes)`)
          }
        } catch { /* ignora */ }
      }

      if (hits >= 2) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `cross-tenant:${template}`, location: template }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: 'critical',
          title: `Cross-tenant: múltiplos IDs respondem em ${template}`,
          description: `${hits} IDs distintos retornaram 200 em ${template}. Indica que recursos de outros tenants/orgs são acessíveis com o mesmo token — falha clássica de isolamento.`,
          endpoint: template,
          evidence: samples.join('\n'),
          recommendation: 'Sempre filtre por tenant do usuário autenticado:\n```typescript\n@Get(\'orgs/:id/users\')\nasync findOrgUsers(@Param(\'id\') id: string, @CurrentUser() user) {\n  if (user.orgId !== id) throw new ForbiddenException();\n  return this.users.findByOrg(id);\n}\n```',
          references: [
            'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            'https://cwe.mitre.org/data/definitions/639.html',
          ],
          createdAt: new Date(),
        })
      }
    }
  }

  private async probeHeaderInjection(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    const candidatePaths = ['/api/me', '/api/profile', '/api/account', '/api/user', '/me', '/profile']

    for (const path of candidatePaths) {
      if (ignore.some(i => path.startsWith(i))) continue

      let baselineStatus: number | null = null
      let baselineLen = 0
      try {
        const baseline = await client.request(path, { timeoutMs: 4_000 })
        baselineStatus = baseline.status
        baselineLen = baseline.raw.length
      } catch { continue }

      if (baselineStatus !== 200) continue

      for (const header of TENANT_HEADERS) {
        try {
          const res = await client.request(path, {
            timeoutMs: 4_000,
            headers: { [header]: '999999' },
          })
          if (res.status === 200 && Math.abs(res.raw.length - baselineLen) > 50) {
            findings.push({
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `tenant-header-injection:${header}:${path}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
              severity: 'high',
              title: `Header de tenant aceito sem validação: ${header} em ${path}`,
              description: `${path} retornou corpo diferente (∆ ${Math.abs(res.raw.length - baselineLen)} bytes) ao injetar ${header}: 999999. O backend pode estar confiando no header em vez do tenant do JWT.`,
              endpoint: path,
              evidence: `Baseline: ${baselineLen}B / Com ${header}: ${res.raw.length}B`,
              recommendation: 'Nunca derive tenant/org do header da request — sempre extraia do JWT/sessão:\n```typescript\nconst orgId = req.user.orgId;  // do token\n// NÃO: const orgId = req.headers[\'x-tenant-id\'];\n```',
              references: [
                'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
              ],
              createdAt: new Date(),
            })
            break
          }
        } catch { /* ignora */ }
      }
    }
  }
}
