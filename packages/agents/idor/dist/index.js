// src/index.ts
import { FractaHttpClient, stableFindingId as stableFindingId2 } from "@fracta/core";

// src/cross-tenant.ts
import { stableFindingId } from "@fracta/core";
var CATEGORY = "security";
var AGENT = "IDOR Agent";
var REFS = [
  "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
  "https://cwe.mitre.org/data/definitions/639.html"
];
function tenantBOwns(p) {
  return p.tenantBStatus === 200;
}
function tenantALeaked(p) {
  return p.tenantAStatus === 200 && p.tenantABytes > 10;
}
function evaluateCrossTenant(input) {
  const { saas, runId, probes } = input;
  if (probes.length === 0) return [];
  const usable = probes.filter(tenantBOwns);
  if (usable.length === 0) {
    return [{
      id: stableFindingId({ saas, camada: CATEGORY, rule: "idor-crosstenant-inconclusive" }),
      runId,
      agent: AGENT,
      category: CATEGORY,
      camada: CATEGORY,
      severity: "info",
      confidence: "high",
      title: "IDOR cross-tenant: inconclusivo (tenant B n\xE3o acessou os pr\xF3prios recursos)",
      description: `O tenant B n\xE3o conseguiu acessar nenhum dos ${probes.length} recurso(s) declarados como seus (status \u2260 200). Sem essa \xE2ncora n\xE3o \xE9 poss\xEDvel provar (nem descartar) vazamento cross-tenant. Confira as credenciais/paths de \`crossTenant.ownedResources\` no targets.yaml.`,
      recommendation: "Ajuste os recursos de B em `crossTenant.ownedResources` para paths que o tenant B realmente acessa (GET 200).",
      references: REFS,
      createdAt: /* @__PURE__ */ new Date()
    }];
  }
  const leaks = usable.filter(tenantALeaked);
  if (leaks.length > 0) {
    return leaks.map((p) => ({
      id: stableFindingId({ saas, camada: CATEGORY, rule: `idor-crosstenant-confirmed:${p.resource}`, location: p.resource }),
      runId,
      agent: AGENT,
      category: CATEGORY,
      camada: CATEGORY,
      severity: "critical",
      confidence: "high",
      title: `IDOR cross-tenant CONFIRMADO: tenant A leu recurso de B (${p.resource})`,
      description: `Provado em runtime: o recurso ${p.resource} PERTENCE ao tenant B (B o acessa com 200), e o tenant A conseguiu l\xEA-lo (HTTP ${p.tenantAStatus}, ${p.tenantABytes} bytes). Isso \xE9 Broken Object Level Authorization: dados de um tenant vazam para outro. N\xE3o \xE9 heur\xEDstica \u2014 \xE9 acesso cruzado real.`,
      endpoint: p.resource,
      evidence: `A: GET ${p.resource} \u2192 ${p.tenantAStatus} (${p.tenantABytes} bytes)${p.tenantABody ? `
${p.tenantABody.slice(0, 200)}` : ""}
B (dono): GET ${p.resource} \u2192 200`,
      recommendation: "Escope TODA leitura de recurso ao tenant/owner do usu\xE1rio autenticado (filtro no `where`, Prisma extension ou Postgres RLS). Nunca confie s\xF3 no ID da rota \u2014 verifique a propriedade antes de retornar.",
      references: REFS,
      createdAt: /* @__PURE__ */ new Date()
    }));
  }
  return [{
    id: stableFindingId({ saas, camada: CATEGORY, rule: "idor-crosstenant-isolated" }),
    runId,
    agent: AGENT,
    category: CATEGORY,
    camada: CATEGORY,
    severity: "info",
    confidence: "high",
    title: "Isolamento multi-tenant confirmado em runtime",
    description: `Verificado com 2 contas: o tenant A foi NEGADO em ${usable.length} recurso(s) que pertencem ao tenant B (B os acessa com 200; A recebeu 403/404). Isolamento cross-tenant OK para os recursos testados \u2014 prova positiva, n\xE3o suposi\xE7\xE3o.`,
    recommendation: "Mantenha o escopo por tenant em toda query. Amplie `crossTenant.ownedResources` para cobrir mais rotas sens\xEDveis.",
    references: REFS,
    createdAt: /* @__PURE__ */ new Date()
  }];
}

// src/index.ts
var PATH_TEMPLATES = [
  "/users/{id}",
  "/api/users/{id}",
  "/api/v1/users/{id}",
  "/api/v2/users/{id}",
  "/clientes/{id}",
  "/api/clientes/{id}",
  "/invoices/{id}",
  "/api/invoices/{id}",
  "/subscriptions/{id}",
  "/api/subscriptions/{id}",
  "/reports/{id}",
  "/api/reports/{id}",
  "/documents/{id}",
  "/api/documents/{id}",
  "/calculos/{id}",
  "/api/calculos/{id}",
  "/processos/{id}",
  "/api/processos/{id}"
];
var ENUM_PATHS = ["/api/users/", "/api/clientes/", "/api/calculos/", "/api/processos/"];
function getIdsForDepth(depth) {
  const base = [1, 2, 999];
  if (depth === "full") return [...base, 3, 99, 100, 1e3];
  if (depth === "paranoid") return [...base, 3, 99, 100, 1e3, "00000000-0000-0000-0000-000000000001"];
  return base;
}
var IdorAgent = class {
  name = "IDOR Agent";
  category = "security";
  concurrency = 2;
  timeoutMs = 6e4;
  async run(scope) {
    const findings = [];
    if (!scope.target.auth) {
      findings.push({
        id: stableFindingId2({ saas: scope.target.name, camada: this.category, rule: "idor-auth-not-configured" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "info",
        title: "IDOR Agent \u2014 autentica\xE7\xE3o n\xE3o configurada",
        description: "Configure auth no targets.yaml para testar IDOR com token de usu\xE1rio autenticado.",
        recommendation: "Adicione auth.credentials no targets.yaml para que o IDOR Agent possa obter um token e testar acesso cruzado entre IDs.",
        createdAt: /* @__PURE__ */ new Date()
      });
      return findings;
    }
    let client;
    try {
      const { credentials, endpoint } = scope.target.auth;
      if (credentials?.email && credentials?.password && endpoint) {
        const result = await FractaHttpClient.withJwt(
          scope.target.url,
          endpoint,
          { email: credentials.email, password: credentials.password }
        );
        client = result.client;
      } else {
        client = new FractaHttpClient(scope.target.url);
      }
    } catch {
      client = new FractaHttpClient(scope.target.url);
    }
    const ids = getIdsForDepth(scope.depth);
    const ignore = scope.target.ignore ?? [];
    for (const template of PATH_TEMPLATES) {
      for (const id of ids) {
        const path = template.replace("{id}", String(id));
        if (ignore.some((i) => path.startsWith(i))) continue;
        try {
          const res = await client.request(path, { timeoutMs: 5e3 });
          if (res.status === 200 && res.raw.length > 10) {
            findings.push({
              id: stableFindingId2({ saas: scope.target.name, camada: this.category, rule: `idor-direct-access:${path}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
              severity: "critical",
              title: `IDOR \u2014 acesso direto por ID: ${path}`,
              description: `${path} retornou HTTP 200 com corpo n\xE3o-vazio. Poss\xEDvel IDOR \u2014 recurso de ID ${id} acess\xEDvel sem verificar propriedade.`,
              endpoint: path,
              evidence: `GET ${path} \u2192 HTTP 200 (${res.raw.length} bytes)
${res.raw.substring(0, 200)}`,
              recommendation: `Sempre verifique que o recurso pertence ao usu\xE1rio autenticado:
\`\`\`typescript
@Get(':id')
async findOne(@Param('id') id: string, @CurrentUser() user: User) {
  const record = await this.service.findOne(id);
  if (record.userId !== user.id) throw new ForbiddenException();
  return record;
}
\`\`\``,
              references: [
                "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                "https://cwe.mitre.org/data/definitions/639.html"
              ],
              createdAt: /* @__PURE__ */ new Date()
            });
          } else if (res.status === 500) {
            findings.push({
              id: stableFindingId2({ saas: scope.target.name, camada: this.category, rule: `idor-error-500:${path}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
              severity: "medium",
              title: `Erro 500 ao acessar ID inexistente: ${path}`,
              description: `${path} retornou HTTP 500 para ID ${id}, indicando falta de tratamento de erro para recursos n\xE3o encontrados.`,
              endpoint: path,
              evidence: `GET ${path} (id=${id}) \u2192 HTTP 500`,
              recommendation: `Trate recursos n\xE3o encontrados com 404:
\`\`\`typescript
if (!record) throw new NotFoundException(\`Recurso ${id} n\xE3o encontrado\`);
\`\`\``,
              references: ["https://owasp.org/www-project-web-security-testing-guide/"],
              createdAt: /* @__PURE__ */ new Date()
            });
          }
        } catch {
        }
      }
    }
    await this.testEnumeration(scope, client, findings, ignore);
    await this.testCrossTenant(scope, findings);
    return findings;
  }
  /**
   * IDOR cross-tenant REAL (2 contas): autentica A e B, confirma que B acessa os
   * próprios recursos e tenta acessá-los como A. A conseguir = vazamento cross-tenant
   * PROVADO (não heurística). Opt-in via `crossTenant` no targets.yaml; read-only.
   */
  async testCrossTenant(scope, findings) {
    const ct = scope.target.crossTenant;
    if (!ct) return;
    const auth = scope.target.auth;
    const aEndpoint = auth?.endpoint;
    const aCreds = auth?.credentials;
    if (!aCreds?.email || !aCreds.password || !aEndpoint) {
      findings.push(this.crossTenantInfo(
        scope,
        "IDOR cross-tenant: requer o tenant A autenticado",
        "O bloco `crossTenant` (tenant B) est\xE1 configurado, mas falta `auth` com `credentials` (email/senha) e `endpoint` do tenant A. O teste cross-tenant precisa das DUAS identidades."
      ));
      return;
    }
    let clientA;
    let clientB;
    try {
      clientA = (await FractaHttpClient.withJwt(scope.target.url, aEndpoint, { email: aCreds.email, password: aCreds.password })).client;
      clientB = (await FractaHttpClient.withJwt(scope.target.url, ct.endpoint ?? aEndpoint, ct.credentials)).client;
    } catch (e) {
      findings.push(this.crossTenantInfo(
        scope,
        "IDOR cross-tenant: inconclusivo (falha ao autenticar A ou B)",
        `N\xE3o foi poss\xEDvel obter token de um dos tenants: ${e instanceof Error ? e.message : String(e)}. Confira credenciais/endpoint.`
      ));
      return;
    }
    const probes = [];
    for (const resource of ct.ownedResources) {
      let tenantBStatus = 0;
      let tenantAStatus = 0;
      let tenantABytes = 0;
      let tenantABody;
      try {
        tenantBStatus = (await clientB.request(resource, { timeoutMs: 5e3 })).status;
      } catch {
      }
      try {
        const ra = await clientA.request(resource, { timeoutMs: 5e3 });
        tenantAStatus = ra.status;
        tenantABytes = ra.raw.length;
        tenantABody = ra.raw;
      } catch {
      }
      probes.push({ resource, tenantBStatus, tenantAStatus, tenantABytes, tenantABody });
    }
    findings.push(...evaluateCrossTenant({ saas: scope.target.name, runId: scope.runId, probes }));
  }
  crossTenantInfo(scope, title, description) {
    return {
      id: stableFindingId2({ saas: scope.target.name, camada: this.category, rule: `idor-crosstenant-setup:${title}` }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "info",
      confidence: "high",
      title,
      description,
      recommendation: "Configure `auth` (tenant A) + `crossTenant` (tenant B, com `ownedResources`) no targets.yaml para provar isolamento multi-tenant.",
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  async testEnumeration(scope, client, findings, ignore) {
    for (const basePath of ENUM_PATHS) {
      if (ignore.some((i) => basePath.startsWith(i))) continue;
      let hits = 0;
      for (let id = 1; id <= 5; id++) {
        try {
          const res = await client.request(`${basePath}${id}`, { timeoutMs: 4e3 });
          if (res.status === 200 && res.raw.length > 10) hits++;
        } catch {
        }
      }
      if (hits >= 3) {
        findings.push({
          id: stableFindingId2({ saas: scope.target.name, camada: this.category, rule: `idor-enumeration:${basePath}`, location: basePath }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "high",
          title: `IDs sequenciais enumer\xE1veis: ${basePath}`,
          description: `${hits}/5 IDs sequenciais em ${basePath} retornaram recursos v\xE1lidos. IDs num\xE9ricos previs\xEDveis facilitam enumera\xE7\xE3o de dados.`,
          endpoint: basePath,
          evidence: `${basePath}1 \u2192 200, ${basePath}2 \u2192 200, ... (${hits}/5 encontrados)`,
          recommendation: "Use UUIDs em vez de IDs sequenciais:\n```typescript\n@PrimaryGeneratedColumn('uuid')\nid: string;\n```",
          references: ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    }
  }
};
export {
  IdorAgent
};
