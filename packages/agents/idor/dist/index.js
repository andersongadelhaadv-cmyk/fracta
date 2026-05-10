// src/index.ts
import { randomUUID } from "crypto";
import { FractaHttpClient } from "@fracta/core";
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
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
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
              id: randomUUID(),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
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
              id: randomUUID(),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
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
    return findings;
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
          id: randomUUID(),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
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
