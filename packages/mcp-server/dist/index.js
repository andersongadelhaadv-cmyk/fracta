// src/index.ts
import { readFile } from "fs/promises";
import { parse as parseYaml } from "yaml";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { FractaOrchestrator } from "@fracta/core";
import { AuthAgent } from "@fracta/agent-auth";
import { HeadersAgent } from "@fracta/agent-headers";
import { IdorAgent } from "@fracta/agent-idor";
import { DocsAgent } from "@fracta/agent-docs";
import { TenantAgent } from "@fracta/agent-tenant";
import { RaceAgent } from "@fracta/agent-race";
import { StripeAgent } from "@fracta/agent-stripe";
import { DependenciesAgent } from "@fracta/agent-dependencies";
import { SecretsAgent } from "@fracta/agent-secrets";
import { StackAgent } from "@fracta/agent-stack";
import { InfraAgent } from "@fracta/agent-infra";
import { ComplianceAgent } from "@fracta/agent-compliance";
import { NestJSSkill } from "@fracta/skill-nestjs";
import { PrismaSkill } from "@fracta/skill-prisma";
import { SupabaseSkill } from "@fracta/skill-supabase";
import { FractaReporter } from "@fracta/reporter";
import { SqliteFindingStore } from "@fracta/store";
import { LlmEnricher } from "@fracta/llm";
import { spawnSync } from "child_process";
import { existsSync } from "fs";
import { createRequire } from "module";
function hasNodeSqlite() {
  try {
    createRequire(import.meta.url)("node:sqlite");
    return true;
  } catch {
    return false;
  }
}
if (!process.env.FRACTA_REEXEC && !hasNodeSqlite()) {
  const node22 = [process.env.FRACTA_NODE, "/opt/node-22/bin/node"].filter((p) => Boolean(p)).find((p) => existsSync(p));
  if (node22 && process.argv[1]) {
    const res = spawnSync(node22, [process.argv[1], ...process.argv.slice(2)], {
      stdio: "inherit",
      env: { ...process.env, FRACTA_REEXEC: "1" }
    });
    process.exit(res.status ?? 0);
  }
}
var TARGETS_CONFIG = process.env.TARGETS_CONFIG ?? "./configs/targets.yaml";
var store;
try {
  store = new SqliteFindingStore(process.env.FRACTA_STATE ?? "./fracta-state.db");
} catch (err) {
  console.error(`[Fracta] Estado entre runs indispon\xEDvel: ${err.message}`);
  console.error(`[Fracta] MCP seguindo SEM regress\xE3o/supress\xE3o (detec\xE7\xE3o intacta).`);
}
var enricher = process.env.FRACTA_LLM === "1" ? new LlmEnricher() : void 0;
async function loadTargets() {
  const raw = await readFile(TARGETS_CONFIG, "utf-8");
  const resolved = raw.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] ?? "");
  const parsed = parseYaml(resolved);
  return Object.entries(parsed.targets).map(([name, t]) => ({ name, ...t }));
}
function buildOrchestrator(depth = "full") {
  const o = new FractaOrchestrator({ depth, failOn: ["critical", "high"], verbose: false, store, enricher });
  o.registerAgents([
    new HeadersAgent(),
    new AuthAgent(),
    new IdorAgent(),
    new DocsAgent(),
    new TenantAgent(),
    new RaceAgent(),
    new StripeAgent(),
    new DependenciesAgent(),
    new SecretsAgent(),
    new StackAgent(),
    new InfraAgent(),
    new ComplianceAgent(),
    new NestJSSkill(),
    new PrismaSkill(),
    new SupabaseSkill()
  ]);
  return o;
}
var lastReports = /* @__PURE__ */ new Map();
var server = new Server(
  { name: "fracta", version: "0.1.0" },
  { capabilities: { tools: {} } }
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_target",
      description: "Executa scan completo de seguran\xE7a em um target configurado no targets.yaml",
      inputSchema: {
        type: "object",
        properties: {
          target: { type: "string", description: "Nome do target (ex: doutor-inss)" },
          depth: { type: "string", enum: ["quick", "full", "paranoid"], description: "Profundidade do scan" }
        },
        required: ["target"]
      }
    },
    {
      name: "test_auth",
      description: "Testa autentica\xE7\xE3o: JWT alg:none, brute force, tokens malformados",
      inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] }
    },
    {
      name: "test_idor",
      description: "Testa IDOR e acesso cruzado entre IDs/tenants",
      inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] }
    },
    {
      name: "check_headers",
      description: "Verifica security headers e configura\xE7\xE3o de CORS",
      inputSchema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] }
    },
    {
      name: "audit_docs",
      description: "Audita arquivos .md do reposit\xF3rio",
      inputSchema: {
        type: "object",
        properties: { repoPath: { type: "string", description: "Caminho do reposit\xF3rio (default: ./)" } }
      }
    },
    {
      name: "get_findings",
      description: "Retorna findings do \xFAltimo scan filtrados por severidade",
      inputSchema: {
        type: "object",
        properties: {
          target: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] }
        }
      }
    },
    {
      name: "generate_report",
      description: "Gera relat\xF3rio do \xFAltimo scan em markdown ou JSON",
      inputSchema: {
        type: "object",
        properties: {
          target: { type: "string" },
          format: { type: "string", enum: ["markdown", "json"], default: "markdown" }
        },
        required: ["target"]
      }
    }
  ]
}));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const a = args ?? {};
  try {
    if (name === "scan_target" || name === "test_auth" || name === "test_idor" || name === "check_headers") {
      const targets = await loadTargets();
      const target = targets.find((t) => t.name === a.target);
      if (!target) return { content: [{ type: "text", text: `Target "${a.target}" n\xE3o encontrado no targets.yaml` }] };
      let agentFilter;
      if (name === "test_auth") agentFilter = ["AUTH Agent"];
      else if (name === "test_idor") agentFilter = ["IDOR Agent"];
      else if (name === "check_headers") agentFilter = ["HEADERS Agent"];
      const scopedTarget = agentFilter ? { ...target, agents: agentFilter } : target;
      const depth = a.depth ?? "full";
      const report = await buildOrchestrator(depth).scan(scopedTarget);
      lastReports.set(a.target, report);
      const reporter = new FractaReporter();
      const { mdPath } = await reporter.save(report);
      const statusTxt = report.verdict === "inconclusive" ? "INCONCLUSIVO (alvo n\xE3o exercido \u2014 aus\xEAncia de achados \u2260 seguro)" : report.passed ? "PASSOU" : "FALHOU";
      const summary = `Scan conclu\xEDdo: ${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium. Status: ${statusTxt}. Relat\xF3rio: ${mdPath}`;
      return { content: [{ type: "text", text: summary }] };
    }
    if (name === "audit_docs") {
      const repoPath = a.repoPath ?? "./";
      const docsTarget = { name: "docs-audit", url: "file://local", stack: [] };
      const o = new FractaOrchestrator({ depth: "full" });
      o.registerAgents([new DocsAgent(repoPath)]);
      const report = await o.scan(docsTarget);
      lastReports.set("docs-audit", report);
      return { content: [{ type: "text", text: `Docs audit: ${report.summary.total} findings. Medium: ${report.summary.medium}, Low: ${report.summary.low}` }] };
    }
    if (name === "get_findings") {
      const report = lastReports.get(a.target ?? "docs-audit");
      if (!report) return { content: [{ type: "text", text: "Nenhum scan encontrado. Execute scan_target primeiro." }] };
      const findings = a.severity ? report.findings.filter((f) => f.severity === a.severity) : report.findings;
      return { content: [{ type: "text", text: JSON.stringify(findings, null, 2) }] };
    }
    if (name === "generate_report") {
      const report = lastReports.get(a.target);
      if (!report) return { content: [{ type: "text", text: "Nenhum scan encontrado. Execute scan_target primeiro." }] };
      const reporter = new FractaReporter();
      const { mdPath, jsonPath } = await reporter.save(report);
      const path = a.format === "json" ? jsonPath : mdPath;
      return { content: [{ type: "text", text: `Relat\xF3rio salvo em: ${path}` }] };
    }
    return { content: [{ type: "text", text: `Tool desconhecida: ${name}` }] };
  } catch (err) {
    return { content: [{ type: "text", text: `Erro: ${String(err)}` }] };
  }
});
var transport = new StdioServerTransport();
await server.connect(transport);
