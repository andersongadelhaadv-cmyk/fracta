// src/types.ts
import { randomUUID, createHash } from "crypto";
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
function stableFindingId(parts) {
  const key = [
    parts.saas.trim().toLowerCase(),
    parts.camada.trim().toLowerCase(),
    parts.rule.trim().toLowerCase(),
    (parts.location ?? "").trim().toLowerCase()
  ].join("|");
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}
var SkippedCheck = class extends Error {
  constructor(motivo) {
    super(motivo);
    this.motivo = motivo;
    this.name = "SkippedCheck";
  }
  motivo;
};

// src/confidence.ts
var FP_PRONE = /(\.(test|spec|stories)\.[cm]?[jt]sx?|[\\/](tests?|__tests__|fixtures?|__fixtures__|mocks?|__mocks__|examples?|samples?|stories|e2e|cypress|playwright)[\\/]|\.(example|sample|mock|fixture)\.|[\\/](demo|seed)s?[\\/]|\.d\.ts$)/i;
function locationOf(f) {
  return [f.title, f.evidence, f.endpoint].filter(Boolean).join(" ");
}
function applyConfidence(findings) {
  return findings.map((f) => {
    let confidence = f.confidence ?? "high";
    if (confidence !== "low" && FP_PRONE.test(locationOf(f))) confidence = "low";
    return confidence === f.confidence ? f : { ...f, confidence };
  });
}

// src/http-client.ts
var FractaHttpClient = class _FractaHttpClient {
  baseUrl;
  baseHeaders;
  clientOptions;
  constructor(baseUrl, baseHeaders = {}, options = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.baseHeaders = {
      "Content-Type": "application/json",
      // UA honesto estilo bot (padrão Googlebot): identifica o Fracta + URL, mas
      // sem a palavra "Scanner" que dispara regras ingênuas de WAF. Não resolve
      // fingerprint TLS (JA3) de bot-protection avançada (ex.: Cloudflare em IP de datacenter).
      "User-Agent": "Mozilla/5.0 (compatible; FractaBot/0.1; +https://fracta.pro)",
      ...baseHeaders
    };
    this.clientOptions = options;
  }
  async request(path, options = {}) {
    const { method = "GET", headers = {}, body, timeoutMs = 1e4, redirect } = options;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const normalizedPath = path.startsWith("/") ? path : `/${path}`;
      const init = {
        method,
        headers: { ...this.baseHeaders, ...headers },
        body: body !== void 0 ? JSON.stringify(body) : void 0,
        signal: controller.signal
      };
      const eff = redirect ?? this.clientOptions.redirect;
      if (eff) init.redirect = eff;
      if (this.clientOptions.dispatcher) init.dispatcher = this.clientOptions.dispatcher;
      const res = await fetch(`${this.baseUrl}${normalizedPath}`, init);
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

// src/health.ts
import { stat } from "fs/promises";
import { join } from "path";
import { connect } from "net";
async function checkTargetHealth(target) {
  const hasRepo = !!target.repoPath;
  const repoAccessible = hasRepo ? await isGitRepo(target.repoPath) : true;
  const stagingApplicable = isHttpUrl(target.url);
  const stagingResponding = stagingApplicable ? await httpResponds(target.url) : void 0;
  const host = target.infra?.host;
  const vpsApplicable = !!host;
  const vpsReachable = host ? await tcpReachable(host) : void 0;
  const status = deriveHealthStatus({
    hasRepo,
    repoAccessible,
    stagingApplicable,
    stagingResponding,
    vpsApplicable,
    vpsReachable
  });
  return { repoAccessible, stagingResponding, vpsReachable, status };
}
function deriveHealthStatus(p) {
  if (p.hasRepo && !p.repoAccessible) return "unreachable";
  const probes = [];
  if (p.stagingApplicable) probes.push(p.stagingResponding === true);
  if (p.vpsApplicable) probes.push(p.vpsReachable === true);
  if (probes.length === 0) return "healthy";
  if (probes.every(Boolean)) return "healthy";
  if (probes.some(Boolean)) return "degraded";
  return "unreachable";
}
function isHttpUrl(url) {
  return !!url && /^https?:\/\//i.test(url);
}
async function isGitRepo(repoPath) {
  try {
    const dir = await stat(repoPath);
    if (!dir.isDirectory()) return false;
    await stat(join(repoPath, ".git"));
    return true;
  } catch {
    return false;
  }
}
async function httpResponds(url, timeoutMs = 5e3) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await fetch(url, { method: "HEAD", signal: controller.signal });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}
function tcpReachable(host, port = 22, timeoutMs = 4e3) {
  return new Promise((resolve) => {
    const socket = connect({ host, port });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", (err) => {
      finish(err.code === "ECONNREFUSED");
    });
  });
}

// src/orchestrator.ts
var SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};
function deriveVerdict(summary, failOn, health) {
  if (failOn.some((s) => summary[s] > 0)) return "failed";
  if (health.status === "unreachable") return "inconclusive";
  return "passed";
}
var FractaOrchestrator = class {
  agents = [];
  options;
  store;
  healthCheck;
  enricher;
  constructor(options = {}) {
    this.options = {
      concurrency: options.concurrency ?? 3,
      failOn: options.failOn ?? ["critical", "high"],
      depth: options.depth ?? "full",
      verbose: options.verbose ?? false
    };
    this.store = options.store;
    this.healthCheck = options.healthCheck ?? checkTargetHealth;
    this.enricher = options.enricher;
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
    const health = await this.healthCheck(target);
    if (target.repoPath && !health.repoAccessible) {
      return this.buildAbortedReport(target, runId, startedAt, health);
    }
    const scope = {
      target,
      depth: this.options.depth,
      agents: activeAgents.map((a) => a.name),
      runId,
      startedAt,
      health
    };
    const checks = [];
    const chunks = chunkArray(activeAgents, this.options.concurrency);
    for (const chunk of chunks) {
      const results = await Promise.all(chunk.map((a) => this.runCheckIsolated(a, scope)));
      checks.push(...results);
    }
    let findings = checks.flatMap((c) => c.findings);
    if (this.store) {
      try {
        const suppressions = target.config?.suppressions ?? [];
        findings = await this.store.applyStatus(target.name, findings, suppressions);
      } catch (err) {
        if (this.options.verbose) console.error(`[Fracta] Store.applyStatus falhou: ${String(err)}`);
      }
    }
    findings = applyConfidence(findings);
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const failSummary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      if (f.status === "suppressed") continue;
      summary.total++;
      summary[f.severity]++;
      if (f.confidence !== "low") {
        failSummary.total++;
        failSummary[f.severity]++;
      }
    }
    const finishedAt = /* @__PURE__ */ new Date();
    const verdict = deriveVerdict(failSummary, this.options.failOn, health);
    const passed = verdict === "passed";
    const targetHealth = health;
    let report = {
      runId,
      target: target.name,
      startedAt,
      finishedAt,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      summary,
      findings,
      passed,
      saas: target.name,
      timestamp: finishedAt.toISOString(),
      targetHealth,
      verdict,
      checks,
      resumo: {
        porSeveridade: {
          critical: summary.critical,
          high: summary.high,
          medium: summary.medium,
          low: summary.low,
          info: summary.info
        },
        regressoes: findings.filter((f) => f.status === "regression").length,
        checksComErro: checks.filter((c) => c.status === "error").map((c) => c.agent),
        checksPulados: checks.filter((c) => c.status === "skipped").map((c) => c.agent)
      }
    };
    if (this.enricher) {
      try {
        report = await this.enricher.enrich(report);
      } catch (err) {
        if (this.options.verbose) console.error(`[Fracta] Enricher falhou: ${String(err)}`);
      }
    }
    if (this.store) {
      try {
        await this.store.recordRun(report);
      } catch (err) {
        if (this.options.verbose) console.error(`[Fracta] Store.recordRun falhou: ${String(err)}`);
      }
    }
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
  /**
   * Executa UM agente de forma isolada: aplica timeout, captura qualquer falha
   * e devolve sempre um CheckResult (ok | error | skipped). Nunca propaga exceção.
   */
  async runCheckIsolated(agent, scope) {
    const camada = agent.category;
    const start = Date.now();
    try {
      const findings = await withTimeout(agent.run(scope), agent.timeoutMs);
      return {
        agent: agent.name,
        camada,
        status: "ok",
        durationMs: Date.now() - start,
        findings: findings.map((f) => normalizeFinding(f, camada))
      };
    } catch (err) {
      const durationMs = Date.now() - start;
      if (err instanceof SkippedCheck) {
        return { agent: agent.name, camada, status: "skipped", motivo: err.motivo, durationMs, findings: [] };
      }
      const motivo = err instanceof Error ? err.message : String(err);
      if (this.options.verbose) console.error(`[Fracta] Check error (${agent.name}): ${motivo}`);
      return { agent: agent.name, camada, status: "error", motivo, durationMs, findings: [] };
    }
  }
  /**
   * Auditoria abortada por repo obrigatório inacessível. Devolve um AuditReport
   * honesto (nenhum check rodou, não passou) sem persistir nada.
   */
  buildAbortedReport(target, runId, startedAt, health) {
    const finishedAt = /* @__PURE__ */ new Date();
    const motivo = `repoPath inacess\xEDvel ou n\xE3o \xE9 um reposit\xF3rio git v\xE1lido: ${target.repoPath}`;
    console.error(`
[Fracta] ${target.name} \u2014 \u26D4 AUDITORIA ABORTADA: ${motivo}`);
    return {
      runId,
      target: target.name,
      startedAt,
      finishedAt,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings: [],
      passed: false,
      saas: target.name,
      timestamp: finishedAt.toISOString(),
      targetHealth: health,
      // Repo obrigatório inacessível: não foi possível auditar → inconclusivo, não "falhou".
      verdict: "inconclusive",
      checks: [],
      resumo: {
        porSeveridade: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        regressoes: 0,
        checksComErro: [],
        checksPulados: []
      }
    };
  }
  printSummary(report) {
    const status = report.verdict === "inconclusive" ? "\u26A0\uFE0F INCONCLUSIVE (alvo n\xE3o exercido)" : report.passed ? "\u2705 PASSED" : "\u274C FAILED";
    console.log(`
[Fracta] ${report.target} \u2014 ${status}`);
    console.log(`  Critical: ${report.summary.critical}  High: ${report.summary.high}  Medium: ${report.summary.medium}  Low: ${report.summary.low}  Info: ${report.summary.info}`);
    if (report.resumo.checksComErro.length > 0) {
      console.log(`  \u26A0 Checks com erro: ${report.resumo.checksComErro.join(", ")}`);
    }
    if (report.resumo.checksPulados.length > 0) {
      console.log(`  \u2298 Checks pulados: ${report.resumo.checksPulados.join(", ")}`);
    }
    console.log(`  Duration: ${report.durationMs}ms  Run ID: ${report.runId}`);
  }
};
function normalizeFinding(f, camada) {
  return {
    ...f,
    camada: f.camada ?? camada,
    status: f.status ?? "open"
  };
}
function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout ap\xF3s ${ms}ms`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}
function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

// src/exec.ts
import { spawn } from "child_process";
var runCommand = (command, args, opts = {}) => {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: opts.cwd,
      // No Windows, npm/gitleaks são .cmd e exigem shell para resolver no PATH.
      shell: process.platform === "win32"
    });
    let stdout = "";
    let stderr = "";
    let timer;
    if (opts.timeoutMs) {
      timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`timeout ap\xF3s ${opts.timeoutMs}ms ao executar: ${command}`));
      }, opts.timeoutMs);
    }
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
    if (opts.input !== void 0) {
      child.stdin.write(opts.input);
      child.stdin.end();
    }
  });
};
export {
  FractaHttpClient,
  FractaOrchestrator,
  KNOWN_STACKS,
  SkippedCheck,
  applyConfidence,
  checkTargetHealth,
  deriveHealthStatus,
  deriveVerdict,
  makeFinding,
  runCommand,
  stableFindingId
};
