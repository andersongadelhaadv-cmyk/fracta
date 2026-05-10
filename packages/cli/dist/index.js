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
import { FractaReporter } from "@fracta/reporter";
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
  --fail-on         Severities that cause exit(1) (default: critical,high)
  --docs-path       Repository path for docs audit (default: ./)
  -v, --verbose     Verbose output
  -h, --help        Show this help
`);
    process.exit(0);
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
    new RaceAgent()
  ];
  const orchestrator = new FractaOrchestrator({
    concurrency: 3,
    failOn,
    depth,
    verbose: values.verbose
  });
  orchestrator.registerAgents(allAgents);
  const reporter = new FractaReporter({ outputDir: values.output });
  let anyFailed = false;
  for (const target of targets) {
    const report = await orchestrator.scan(target);
    const { mdPath, jsonPath } = await reporter.save(report);
    console.log(`
[Fracta] Reports saved:`);
    console.log(`  Markdown: ${mdPath}`);
    console.log(`  JSON:     ${jsonPath}`);
    if (!report.passed) anyFailed = true;
  }
  process.exit(anyFailed ? 1 : 0);
}
main().catch((err) => {
  console.error("[Fracta] Fatal error:", err);
  process.exit(1);
});
