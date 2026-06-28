// src/index.ts
import { FractaHttpClient, stableFindingId } from "@fracta/core";
var STUDIO_PATHS = ["/prisma", "/prisma-studio", "/_prisma", "/admin/prisma", "/studio"];
var TRIGGER_PATHS = [
  "/api/users",
  "/api/auth/register",
  "/api/auth/signup",
  "/api/clientes",
  "/api/usuarios"
];
var PRISMA_LEAK_PATTERNS = [
  /\bPrismaClient(?:KnownRequestError|ValidationError|UnknownRequestError)\b/,
  /\bP\d{4}\b/,
  /Unique constraint failed/i,
  /Foreign key constraint failed/i,
  /Invalid `prisma\./i,
  /at\s+\/[\w/.-]+\/@prisma\/client/
];
function findLeak(body) {
  for (const re of PRISMA_LEAK_PATTERNS) {
    if (re.test(body)) return re;
  }
  return null;
}
var PrismaSkill = class {
  name = "Prisma Skill";
  category = "security";
  concurrency = 2;
  timeoutMs = 6e4;
  async run(scope) {
    const findings = [];
    const { target } = scope;
    if (!target.stack.includes("prisma")) return findings;
    const client = new FractaHttpClient(target.url);
    const ignore = target.ignore ?? [];
    await this.probeStudio(scope, client, findings, ignore);
    await this.probeErrorLeak(scope, client, findings, ignore);
    return findings;
  }
  async probeStudio(scope, client, findings, ignore) {
    for (const path of STUDIO_PATHS) {
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, { timeoutMs: 4e3 });
        if (res.status === 200 && /prisma\s+studio/i.test(res.raw.substring(0, 4e3))) {
          findings.push({
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `prisma-studio-exposed:${path}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
            severity: "critical",
            title: `Prisma Studio exposto: ${path}`,
            description: `${path} parece servir o Prisma Studio publicamente. Studio d\xE1 acesso CRUD irrestrito ao banco \u2014 qualquer pessoa pode ler/editar/deletar dados.`,
            endpoint: path,
            evidence: `GET ${path} \u2192 HTTP 200 (${res.raw.length} bytes \u2014 body cont\xE9m "Prisma Studio")`,
            recommendation: "Nunca exponha o Studio em produ\xE7\xE3o. Rode local via `npx prisma studio` e bloqueie qualquer proxy/ingress nessa rota.",
            references: ["https://www.prisma.io/docs/orm/tools/prisma-studio"],
            createdAt: /* @__PURE__ */ new Date()
          });
          return;
        }
      } catch {
      }
    }
  }
  async probeErrorLeak(scope, client, findings, ignore) {
    const bogusBody = {
      email: "fracta-test@example.com",
      password: "fracta-test-9999",
      ___fracta_trigger__: { nested: { deep: "value" } }
    };
    for (const path of TRIGGER_PATHS) {
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, {
          method: "POST",
          body: bogusBody,
          timeoutMs: 5e3
        });
        if (res.status === 404) continue;
        const leak = findLeak(res.raw);
        if (leak) {
          findings.push({
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `prisma-error-leak:${path}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
            severity: "medium",
            title: `Erro Prisma vazado em resposta: ${path}`,
            description: `POST em ${path} retornou corpo com padr\xE3o Prisma (${leak.source}). Vazar nomes de model/coluna ou c\xF3digos como P2002 ajuda atacantes a mapear o schema do banco.`,
            endpoint: path,
            evidence: `POST ${path} \u2192 HTTP ${res.status}
${res.raw.substring(0, 300).replace(/\s+/g, " ").trim()}`,
            recommendation: "Sempre traduza erros do Prisma para respostas opacas em produ\xE7\xE3o:\n```typescript\ntry {\n  await prisma.user.create({ data });\n} catch (e) {\n  if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {\n    throw new ConflictException('Recurso j\xE1 existe');\n  }\n  throw new InternalServerErrorException();\n}\n```",
            references: [
              "https://www.prisma.io/docs/orm/reference/error-reference",
              "https://owasp.org/www-community/Improper_Error_Handling"
            ],
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
  PrismaSkill
};
