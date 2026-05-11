// src/index.ts
import { randomUUID } from "crypto";
import { FractaHttpClient } from "@fracta/core";
var SWAGGER_PATHS = [
  "/api",
  "/api/docs",
  "/api/swagger",
  "/api-docs",
  "/api-json",
  "/docs",
  "/swagger",
  "/swagger-ui",
  "/swagger.json",
  "/openapi.json"
];
var HEALTH_PATHS = ["/health", "/healthz", "/api/health", "/api/healthz", "/api/__healthcheck"];
var HEALTH_LEAK_PATTERNS = [
  /\b(NODE_ENV|DATABASE_URL|REDIS_URL|JWT_SECRET|STRIPE_|SUPABASE_)/i,
  /password\s*[:=]/i,
  /\b(home|usr|src)\/[\w/.-]+\/node_modules\b/,
  /\bcom\.amazonaws\b/i
];
function looksLikeSwagger(body) {
  const lower = body.substring(0, 4e3).toLowerCase();
  return lower.includes("swagger") || lower.includes("openapi") || lower.includes("redoc") || lower.includes('"paths"') && lower.includes('"info"');
}
var NestJSSkill = class {
  name = "NestJS Skill";
  category = "security";
  concurrency = 2;
  timeoutMs = 6e4;
  async run(scope) {
    const findings = [];
    const { target } = scope;
    if (!target.stack.includes("nestjs")) return findings;
    const client = new FractaHttpClient(target.url);
    const ignore = target.ignore ?? [];
    await this.probeSwagger(scope, client, findings, ignore);
    await this.probeHealth(scope, client, findings, ignore);
    return findings;
  }
  async probeSwagger(scope, client, findings, ignore) {
    for (const path of SWAGGER_PATHS) {
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, { timeoutMs: 4e3 });
        if (res.status === 200 && looksLikeSwagger(res.raw)) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: "high",
            title: `Swagger/OpenAPI exposto: ${path}`,
            description: `${path} retornou conte\xFAdo de documenta\xE7\xE3o Swagger/OpenAPI. Em produ\xE7\xE3o, isso vaza estrutura completa da API (rotas, params, schemas) e facilita enumera\xE7\xE3o de endpoints para um atacante.`,
            endpoint: path,
            evidence: `GET ${path} \u2192 HTTP 200 (${res.raw.length} bytes)
${res.raw.substring(0, 200).replace(/\s+/g, " ").trim()}`,
            recommendation: "Desative Swagger em produ\xE7\xE3o:\n```typescript\nif (process.env.NODE_ENV !== 'production') {\n  const config = new DocumentBuilder().setTitle('API').build();\n  SwaggerModule.setup('api', app, SwaggerModule.createDocument(app, config));\n}\n```",
            references: [
              "https://docs.nestjs.com/openapi/introduction",
              "https://owasp.org/www-project-api-security/"
            ],
            createdAt: /* @__PURE__ */ new Date()
          });
          return;
        }
      } catch {
      }
    }
  }
  async probeHealth(scope, client, findings, ignore) {
    for (const path of HEALTH_PATHS) {
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, { timeoutMs: 4e3 });
        if (res.status !== 200 || res.raw.length < 10) continue;
        const leaked = HEALTH_LEAK_PATTERNS.find((re) => re.test(res.raw));
        if (leaked) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: "medium",
            title: `Health endpoint vaza informa\xE7\xE3o sens\xEDvel: ${path}`,
            description: `${path} retornou corpo contendo padr\xE3o sens\xEDvel (${leaked.source}). Health endpoints p\xFAblicos n\xE3o devem expor env vars, paths de filesystem ou credenciais.`,
            endpoint: path,
            evidence: `GET ${path} \u2192 HTTP 200
${res.raw.substring(0, 300).replace(/\s+/g, " ").trim()}`,
            recommendation: "Use @nestjs/terminus com indicators m\xEDnimos (db ping, memory) e nunca inclua env/configs no payload:\n```typescript\n@Get('health')\n@HealthCheck()\ncheck() {\n  return this.health.check([() => this.db.pingCheck('database')]);\n}\n```",
            references: ["https://docs.nestjs.com/recipes/terminus"],
            createdAt: /* @__PURE__ */ new Date()
          });
          return;
        }
      } catch {
      }
    }
  }
};
export {
  NestJSSkill
};
