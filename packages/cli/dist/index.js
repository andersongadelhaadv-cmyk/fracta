#!/usr/bin/env node

// src/index.ts
import { readFile } from "fs/promises";
import { parseArgs } from "util";
import { parse as parseYaml } from "yaml";
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
var BANNER = `
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u255A\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255D\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557
\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551        \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551
\u2588\u2588\u2554\u2550\u2550\u255D  \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551        \u2588\u2588\u2551   \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551
\u2588\u2588\u2551     \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551\u255A\u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2551   \u2588\u2588\u2551  \u2588\u2588\u2551
\u255A\u2550\u255D     \u255A\u2550\u255D  \u255A\u2550\u255D\u255A\u2550\u255D  \u255A\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D   \u255A\u2550\u255D   \u255A\u2550\u255D  \u255A\u2550\u255D

The Complete SaaS Audit Framework \u2014 v0.1.0
`;
async function loadTargets(configPath) {
  const raw = await readFile(configPath, "utf-8");
  const resolved = raw.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] ?? "");
  const parsed = parseYaml(resolved);
  return Object.entries(parsed.targets).map(([name, t]) => ({ name, ...t }));
}
async function main() {
  console.log(BANNER);
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      target: { type: "string", short: "t" },
      config: { type: "string", short: "c", default: "./configs/targets.yaml" },
      depth: { type: "string", short: "d", default: "full" },
      output: { type: "string", short: "o", default: "./fracta-reports" },
      state: { type: "string", default: "./fracta-state.db" },
      "no-state": { type: "boolean", default: false },
      "no-llm": { type: "boolean", default: false },
      "fail-on": { type: "string", default: "critical,high" },
      "docs-path": { type: "string", default: "./" },
      verbose: { type: "boolean", short: "v", default: false },
      help: { type: "boolean", short: "h", default: false }
    }
  });
  const command = positionals[0] ?? "scan";
  if (values.help || command === "help") {
    console.log(`
Usage: fracta <command> [options]

Commands:
  scan    Run full security scan (default)
  docs    Run documentation audit only

Options:
  -t, --target      Target name from targets.yaml (default: all)
  -c, --config      Path to targets.yaml (default: ./configs/targets.yaml)
  -d, --depth       Scan depth: quick | full | paranoid (default: full)
  -o, --output      Output directory (default: ./fracta-reports)
  --state           SQLite state file for regression/suppression (default: ./fracta-state.db)
  --no-state        Disable cross-run state (no regression/suppression)
  --no-llm          Disable the LLM edge (prioritization/fix drafting)
  --fail-on         Severities that cause exit(1) (default: critical,high)
  --docs-path       Repository path for docs audit (default: ./)
  -v, --verbose     Verbose output
  -h, --help        Show this help
`);
    process.exit(0);
  }
  if (command === "scan" && !values.target) {
    console.error("[Fracta] --target \xE9 obrigat\xF3rio: o Fracta audita UM SaaS por vez (blast radius contido).");
    console.error("         Ex: fracta scan --target doutor-inss");
    process.exit(1);
  }
  let targets;
  try {
    targets = await loadTargets(values.config);
  } catch (err) {
    console.error(`[Fracta] Error reading config: ${values.config}
${String(err)}`);
    process.exit(1);
  }
  if (values.target) {
    targets = targets.filter((t) => t.name === values.target);
    if (targets.length === 0) {
      console.error(`[Fracta] Target "${values.target}" not found in ${values.config}`);
      process.exit(1);
    }
  }
  const depth = values.depth ?? "full";
  const failOn = values["fail-on"].split(",").map((s) => s.trim());
  const docsPath = values["docs-path"];
  const allAgents = command === "docs" ? [new DocsAgent(docsPath)] : [
    new HeadersAgent(),
    new AuthAgent(),
    new IdorAgent(),
    new DocsAgent(docsPath),
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
  ];
  const store = values["no-state"] ? void 0 : new SqliteFindingStore(values.state);
  const enricher = values["no-llm"] ? void 0 : new LlmEnricher({ verbose: values.verbose });
  const orchestrator = new FractaOrchestrator({
    concurrency: 3,
    failOn,
    depth,
    verbose: values.verbose,
    store,
    enricher
  });
  orchestrator.registerAgents(allAgents);
  const reporter = new FractaReporter({ outputDir: values.output });
  let anyFailed = false;
  try {
    for (const target of targets) {
      const report = await orchestrator.scan(target);
      const { mdPath, jsonPath } = await reporter.save(report);
      console.log(`
[Fracta] Reports saved:`);
      console.log(`  Markdown: ${mdPath}`);
      console.log(`  JSON:     ${jsonPath}`);
      if (report.resumo.regressoes > 0) {
        console.log(`  \u23EA Regress\xF5es detectadas: ${report.resumo.regressoes}`);
      }
      if (!report.passed) anyFailed = true;
    }
  } finally {
    store?.close();
  }
  process.exit(anyFailed ? 1 : 0);
}
main().catch((err) => {
  console.error("[Fracta] Fatal error:", err);
  process.exit(1);
});
