// src/types.ts
import { randomUUID } from "crypto";
var KNOWN_STACKS = [
  "nestjs",
  "nextjs",
  "prisma",
  "stripe",
  "supabase",
  "whatsapp",
  "redis",
  "docker"
];
function makeFinding(partial) {
  return {
    ...partial,
    id: randomUUID(),
    createdAt: /* @__PURE__ */ new Date()
  };
}

// src/http-client.ts
var FractaHttpClient = class _FractaHttpClient {
  baseUrl;
  baseHeaders;
  constructor(baseUrl, baseHeaders = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.baseHeaders = {
      "Content-Type": "application/json",
      "User-Agent": "Fracta-Security-Scanner/0.1",
      ...baseHeaders
    };
  }
  async request(path, options = {}) {
    const { method = "GET", headers = {}, body, timeoutMs = 1e4 } = options;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const normalizedPath = path.startsWith("/") ? path : `/${path}`;
      const res = await fetch(`${this.baseUrl}${normalizedPath}`, {
        method,
        headers: { ...this.baseHeaders, ...headers },
        body: body !== void 0 ? JSON.stringify(body) : void 0,
        signal: controller.signal
      });
      const raw = await res.text();
      let parsed = raw;
      const ct = res.headers.get("content-type") ?? "";
      if (ct.includes("application/json")) {
        try {
          parsed = JSON.parse(raw);
        } catch {
        }
      }
      const responseHeaders = {};
      res.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });
      return { status: res.status, headers: responseHeaders, body: parsed, raw };
    } finally {
      clearTimeout(timer);
    }
  }
  withHeaders(extra) {
    return new _FractaHttpClient(this.baseUrl, { ...this.baseHeaders, ...extra });
  }
  static async withJwt(baseUrl, authEndpoint, credentials) {
    const tmp = new _FractaHttpClient(baseUrl);
    const res = await tmp.request(authEndpoint, {
      method: "POST",
      body: credentials
    });
    if (res.status >= 400) {
      throw new Error(
        `Auth failed: ${authEndpoint} returned HTTP ${res.status}. Body: ${res.raw.substring(0, 200)}`
      );
    }
    const data = res.body;
    const token = data?.access_token ?? data?.token ?? data?.accessToken ?? data?.data?.token;
    if (!token) {
      throw new Error(`Auth failed: no token in response from ${authEndpoint}`);
    }
    const client = new _FractaHttpClient(baseUrl, { Authorization: `Bearer ${token}` });
    return { client, token };
  }
};

// src/orchestrator.ts
import { randomUUID as randomUUID2 } from "crypto";
var SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};
var FractaOrchestrator = class {
  agents = [];
  options;
  constructor(options = {}) {
    this.options = {
      concurrency: options.concurrency ?? 3,
      failOn: options.failOn ?? ["critical", "high"],
      depth: options.depth ?? "full",
      verbose: options.verbose ?? false
    };
  }
  registerAgent(agent) {
    this.agents.push(agent);
    return this;
  }
  registerAgents(agents) {
    agents.forEach((a) => this.registerAgent(a));
    return this;
  }
  async scan(target) {
    const runId = randomUUID2();
    const startedAt = /* @__PURE__ */ new Date();
    const activeAgents = target.agents && target.agents.length > 0 ? this.agents.filter((a) => target.agents.includes(a.name)) : this.agents;
    if (this.options.verbose) {
      console.log(`
[Fracta] Scanning: ${target.name} (${target.url})`);
      console.log(`[Fracta] Agents: ${activeAgents.map((a) => a.name).join(", ")}`);
      console.log(`[Fracta] Depth: ${this.options.depth}`);
    }
    const scope = {
      target,
      depth: this.options.depth,
      agents: activeAgents.map((a) => a.name),
      runId,
      startedAt
    };
    const findings = [];
    const chunks = chunkArray(activeAgents, this.options.concurrency);
    for (const chunk of chunks) {
      const results = await Promise.allSettled(chunk.map((a) => a.run(scope)));
      for (const result of results) {
        if (result.status === "fulfilled") {
          findings.push(...result.value);
        } else {
          console.error(`[Fracta] Agent error:`, result.reason);
        }
      }
    }
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      summary.total++;
      summary[f.severity]++;
    }
    const finishedAt = /* @__PURE__ */ new Date();
    const passed = !this.options.failOn.some((s) => summary[s] > 0);
    const report = {
      runId,
      target: target.name,
      startedAt,
      finishedAt,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      summary,
      findings,
      passed
    };
    this.printSummary(report);
    return report;
  }
  async scanAll(targets) {
    const reports = [];
    for (const target of targets) {
      reports.push(await this.scan(target));
    }
    return reports;
  }
  printSummary(report) {
    const status = report.passed ? "\u2705 PASSED" : "\u274C FAILED";
    console.log(`
[Fracta] ${report.target} \u2014 ${status}`);
    console.log(`  Critical: ${report.summary.critical}  High: ${report.summary.high}  Medium: ${report.summary.medium}  Low: ${report.summary.low}  Info: ${report.summary.info}`);
    console.log(`  Duration: ${report.durationMs}ms  Run ID: ${report.runId}`);
  }
};
function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
export {
  FractaHttpClient,
  FractaOrchestrator,
  KNOWN_STACKS,
  makeFinding
};
