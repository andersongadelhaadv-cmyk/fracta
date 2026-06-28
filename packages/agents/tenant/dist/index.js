// src/index.ts
import { FractaHttpClient, stableFindingId } from "@fracta/core";
var ADMIN_PATHS = [
  "/api/admin",
  "/api/admin/users",
  "/api/admin/tenants",
  "/api/admin/organizations",
  "/api/admin/dashboard",
  "/api/admin/stats",
  "/admin",
  "/admin/users",
  "/admin/api",
  "/api/_internal",
  "/api/internal",
  "/internal"
];
var TENANT_LIST_PATHS = [
  "/api/tenants",
  "/api/orgs",
  "/api/organizations",
  "/api/companies",
  "/api/empresas",
  "/api/clientes/all",
  "/api/escritorios"
];
var TENANT_TEMPLATES = [
  "/api/orgs/{id}/users",
  "/api/orgs/{id}/data",
  "/api/tenants/{id}/users",
  "/api/tenants/{id}/data",
  "/api/organizations/{id}/members",
  "/api/organizations/{id}/billing",
  "/api/companies/{id}/employees",
  "/api/empresas/{id}/dados",
  "/api/escritorios/{id}/clientes"
];
var TENANT_HEADERS = ["X-Tenant-ID", "X-Tenant", "X-Org-ID", "X-Organization-Id", "X-Company-Id"];
function getIdsForDepth(depth) {
  const base = [1, 2];
  if (depth === "full") return [...base, 3, 99];
  if (depth === "paranoid") return [...base, 3, 99, 1e3];
  return base;
}
function shortBody(raw) {
  return raw.substring(0, 200).replace(/\s+/g, " ").trim();
}
var TenantAgent = class {
  name = "TENANT Agent";
  category = "security";
  concurrency = 2;
  timeoutMs = 9e4;
  async run(scope) {
    const findings = [];
    const { target } = scope;
    let client;
    let authenticated = false;
    if (target.auth?.credentials?.email && target.auth?.credentials?.password && target.auth?.endpoint) {
      try {
        const result = await FractaHttpClient.withJwt(
          target.url,
          target.auth.endpoint,
          { email: target.auth.credentials.email, password: target.auth.credentials.password }
        );
        client = result.client;
        authenticated = true;
      } catch {
        client = new FractaHttpClient(target.url);
      }
    } else {
      client = new FractaHttpClient(target.url);
    }
    if (!authenticated) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "tenant-auth-not-configured" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "info",
        title: "TENANT Agent \u2014 autentica\xE7\xE3o n\xE3o configurada",
        description: "TENANT Agent testa isolamento entre tenants. Sem credenciais v\xE1lidas s\xF3 consegue verificar exposi\xE7\xE3o n\xE3o-autenticada de rotas admin/tenant.",
        recommendation: "Configure auth.credentials no targets.yaml para que o TENANT Agent possa testar acesso cruzado com um token autenticado.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    const ignore = target.ignore ?? [];
    await this.probeAdminPaths(scope, client, findings, ignore, authenticated);
    await this.probeTenantPaths(scope, client, findings, ignore);
    if (authenticated) {
      await this.probeHeaderInjection(scope, client, findings, ignore);
    }
    return findings;
  }
  async probeAdminPaths(scope, client, findings, ignore, authenticated) {
    for (const path of [...ADMIN_PATHS, ...TENANT_LIST_PATHS]) {
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, { timeoutMs: 5e3 });
        if (res.status === 200 && res.raw.length > 10) {
          const severity = authenticated ? "critical" : "high";
          findings.push({
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `admin-route-exposed:${path}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
            severity,
            title: `Rota administrativa/multi-tenant exposta: ${path}`,
            description: authenticated ? `${path} retornou HTTP 200 com um token de usu\xE1rio comum. Endpoints administrativos n\xE3o devem ser acess\xEDveis sem checagem de role.` : `${path} retornou HTTP 200 sem autentica\xE7\xE3o. Listagem de tenants/orgs/admin n\xE3o deveria ser p\xFAblica.`,
            endpoint: path,
            evidence: `GET ${path} \u2192 HTTP 200 (${res.raw.length} bytes)
${shortBody(res.raw)}`,
            recommendation: "Proteja rotas administrativas com guard de role e nunca exponha listagens globais de tenants:\n```typescript\n@UseGuards(JwtAuthGuard, RolesGuard)\n@Roles('admin')\n@Get('admin/users')\nlistAll() { ... }\n```",
            references: [
              "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
              "https://cwe.mitre.org/data/definitions/285.html"
            ],
            createdAt: /* @__PURE__ */ new Date()
          });
        }
      } catch {
      }
    }
  }
  async probeTenantPaths(scope, client, findings, ignore) {
    const ids = getIdsForDepth(scope.depth);
    for (const template of TENANT_TEMPLATES) {
      let hits = 0;
      const samples = [];
      for (const id of ids) {
        const path = template.replace("{id}", String(id));
        if (ignore.some((i) => path.startsWith(i))) continue;
        try {
          const res = await client.request(path, { timeoutMs: 5e3 });
          if (res.status === 200 && res.raw.length > 10) {
            hits++;
            samples.push(`${path} \u2192 200 (${res.raw.length} bytes)`);
          }
        } catch {
        }
      }
      if (hits >= 2) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `cross-tenant:${template}`, location: template }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "critical",
          title: `Cross-tenant: m\xFAltiplos IDs respondem em ${template}`,
          description: `${hits} IDs distintos retornaram 200 em ${template}. Indica que recursos de outros tenants/orgs s\xE3o acess\xEDveis com o mesmo token \u2014 falha cl\xE1ssica de isolamento.`,
          endpoint: template,
          evidence: samples.join("\n"),
          recommendation: "Sempre filtre por tenant do usu\xE1rio autenticado:\n```typescript\n@Get('orgs/:id/users')\nasync findOrgUsers(@Param('id') id: string, @CurrentUser() user) {\n  if (user.orgId !== id) throw new ForbiddenException();\n  return this.users.findByOrg(id);\n}\n```",
          references: [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "https://cwe.mitre.org/data/definitions/639.html"
          ],
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    }
  }
  async probeHeaderInjection(scope, client, findings, ignore) {
    const candidatePaths = ["/api/me", "/api/profile", "/api/account", "/api/user", "/me", "/profile"];
    for (const path of candidatePaths) {
      if (ignore.some((i) => path.startsWith(i))) continue;
      let baselineStatus = null;
      let baselineLen = 0;
      try {
        const baseline = await client.request(path, { timeoutMs: 4e3 });
        baselineStatus = baseline.status;
        baselineLen = baseline.raw.length;
      } catch {
        continue;
      }
      if (baselineStatus !== 200) continue;
      for (const header of TENANT_HEADERS) {
        try {
          const res = await client.request(path, {
            timeoutMs: 4e3,
            headers: { [header]: "999999" }
          });
          if (res.status === 200 && Math.abs(res.raw.length - baselineLen) > 50) {
            findings.push({
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `tenant-header-injection:${header}:${path}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
              severity: "high",
              title: `Header de tenant aceito sem valida\xE7\xE3o: ${header} em ${path}`,
              description: `${path} retornou corpo diferente (\u2206 ${Math.abs(res.raw.length - baselineLen)} bytes) ao injetar ${header}: 999999. O backend pode estar confiando no header em vez do tenant do JWT.`,
              endpoint: path,
              evidence: `Baseline: ${baselineLen}B / Com ${header}: ${res.raw.length}B`,
              recommendation: "Nunca derive tenant/org do header da request \u2014 sempre extraia do JWT/sess\xE3o:\n```typescript\nconst orgId = req.user.orgId;  // do token\n// N\xC3O: const orgId = req.headers['x-tenant-id'];\n```",
              references: [
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
              ],
              createdAt: /* @__PURE__ */ new Date()
            });
            break;
          }
        } catch {
        }
      }
    }
  }
};
export {
  TenantAgent
};
