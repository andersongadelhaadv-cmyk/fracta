#!/usr/bin/env node
import {
  FractaHttpClient,
  FractaOrchestrator,
  SkippedCheck,
  assertUsableTarget,
  runCommand,
  stableFindingId
} from "./chunk-U24RMSTQ.js";
import "./chunk-JSBRDJBE.js";

// src/index.ts
import { readFile as readFile6, writeFile as writeFile2, access, mkdir as mkdir2 } from "fs/promises";
import { dirname } from "path";
import { parse as parseYaml } from "yaml";

// src/args.ts
import { parseArgs } from "util";
var CLI_OPTIONS = {
  target: { type: "string", short: "t" },
  config: { type: "string", short: "c", default: "./configs/targets.yaml" },
  depth: { type: "string", short: "d", default: "full" },
  output: { type: "string", short: "o", default: "./fracta-reports" },
  state: { type: "string", default: "./fracta-state.db" },
  "no-state": { type: "boolean", default: false },
  llm: { type: "boolean", default: false },
  "no-llm": { type: "boolean", default: false },
  "fail-on": { type: "string", default: "critical,high" },
  "docs-path": { type: "string", default: "./" },
  force: { type: "boolean", default: false },
  verbose: { type: "boolean", short: "v", default: false },
  version: { type: "boolean", short: "V", default: false },
  help: { type: "boolean", short: "h", default: false }
};
var CliUsageError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "CliUsageError";
  }
};
function parseCliArgs(argv) {
  try {
    return parseArgs({
      args: argv,
      allowPositionals: true,
      options: CLI_OPTIONS
    });
  } catch (e) {
    const err = e;
    if (typeof err.code === "string" && err.code.startsWith("ERR_PARSE_ARGS")) {
      const opt = err.message.match(/'(-[^']+)'/)?.[1] ?? "(op\xE7\xE3o inv\xE1lida)";
      throw new CliUsageError(
        `[Fracta] Op\xE7\xE3o desconhecida: ${opt}. Rode "fracta --help" para ver as op\xE7\xF5es v\xE1lidas.`
      );
    }
    throw e;
  }
}

// ../agents/auth/dist/index.js
var COMMON_ENDPOINTS = [
  "/api/users",
  "/api/admin",
  "/api/dashboard",
  "/api/reports",
  "/api/clientes",
  "/api/calculos",
  "/api/processos",
  "/api/invoices",
  "/api/subscriptions",
  "/api/billing",
  "/admin",
  "/api/v1/users",
  "/api/v2/users",
  "/api/me",
  "/api/profile"
];
function makeAlgNoneJwt() {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ role: "ADMIN", sub: "1", iat: Math.floor(Date.now() / 1e3) })).toString("base64url");
  return `${header}.${payload}.`;
}
var MALFORMED_TOKENS = [
  "invalid.token.here",
  makeAlgNoneJwt(),
  "Bearer null",
  "Bearer undefined",
  "Bearer ",
  "null",
  ""
];
var AuthAgent = class {
  name = "AUTH Agent";
  category = "security";
  concurrency = 2;
  timeoutMs = 3e4;
  async run(scope) {
    const findings = [];
    const client = new FractaHttpClient(scope.target.url);
    await this.testUnauthenticatedAccess(scope, client, findings);
    await this.testMalformedTokens(scope, client, findings);
    await this.testRateLimit(scope, findings);
    return findings;
  }
  async testUnauthenticatedAccess(scope, client, findings) {
    const ignore = scope.target.ignore ?? [];
    for (const endpoint of COMMON_ENDPOINTS) {
      if (ignore.some((i) => endpoint.startsWith(i))) continue;
      try {
        const res = await client.request(endpoint, { timeoutMs: 5e3 });
        if (res.status === 200 && res.raw.length > 10) {
          findings.push({
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `unauth-access:${endpoint}`, location: endpoint }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
            severity: "critical",
            title: `Endpoint desprotegido: ${endpoint}`,
            description: `${endpoint} retornou HTTP 200 sem autentica\xE7\xE3o, expondo dados potencialmente sens\xEDveis.`,
            endpoint,
            evidence: `GET ${endpoint} \u2192 HTTP 200 (${res.raw.length} bytes)`,
            recommendation: `Adicione guard de autentica\xE7\xE3o no endpoint:
\`\`\`typescript
@UseGuards(JwtAuthGuard)
@Get('${endpoint.replace("/api/", "")}')
async findAll() { ... }
\`\`\``,
            references: ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
            createdAt: /* @__PURE__ */ new Date()
          });
        }
      } catch {
      }
    }
  }
  async testMalformedTokens(scope, client, findings) {
    const testEndpoints = COMMON_ENDPOINTS.slice(0, 5);
    const ignore = scope.target.ignore ?? [];
    for (const endpoint of testEndpoints) {
      if (ignore.some((i) => endpoint.startsWith(i))) continue;
      for (const token of MALFORMED_TOKENS) {
        try {
          const res = await client.request(endpoint, {
            headers: { Authorization: token },
            timeoutMs: 5e3
          });
          if (res.status === 200 && res.raw.length > 10) {
            findings.push({
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `malformed-token-accepted:${endpoint}`, location: endpoint }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
              severity: "critical",
              title: `Token malformado aceito: ${endpoint}`,
              description: `${endpoint} retornou HTTP 200 com token inv\xE1lido "${token.substring(0, 30)}..."`,
              endpoint,
              evidence: `Authorization: ${token.substring(0, 50)}
\u2192 HTTP 200`,
              recommendation: "Valide tokens JWT com biblioteca robusta e rejeite tokens com alg:none:\n```typescript\nJwtModule.register({ secret: process.env.JWT_SECRET, signOptions: { algorithm: 'HS256' } })\n```",
              references: [
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235"
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
  async testRateLimit(scope, findings) {
    const authEndpoint = scope.target.auth?.endpoint;
    if (!authEndpoint) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "rate-limit-not-tested" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "info",
        title: "Rate limit n\xE3o testado \u2014 auth.endpoint n\xE3o configurado",
        description: "Configure auth.endpoint no targets.yaml para testar prote\xE7\xE3o contra brute force.",
        recommendation: "Adicione auth.endpoint no targets.yaml:\n```yaml\nauth:\n  endpoint: /api/auth/login\n```",
        createdAt: /* @__PURE__ */ new Date()
      });
      return;
    }
    const client = new FractaHttpClient(scope.target.url);
    const body = { email: "brute@fracta.test", password: "wrong-password-fracta-12345" };
    const requests = Array.from(
      { length: 10 },
      () => client.request(authEndpoint, { method: "POST", body, timeoutMs: 5e3 }).catch(() => null)
    );
    const results = await Promise.all(requests);
    const rateLimited = results.filter((r) => r?.status === 429).length;
    if (rateLimited < 2) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `brute-force:${authEndpoint}`, location: authEndpoint }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "high",
        title: "Rate limiting ausente no endpoint de login",
        description: `10 requisi\xE7\xF5es simult\xE2neas de login inv\xE1lido retornaram apenas ${rateLimited} respostas 429. Prote\xE7\xE3o contra brute force insuficiente.`,
        endpoint: authEndpoint,
        evidence: `10 POST ${authEndpoint} com credenciais erradas \u2192 ${rateLimited}/10 retornaram 429`,
        recommendation: "Implemente rate limiting no endpoint de login:\n```typescript\nimport { ThrottlerGuard } from '@nestjs/throttler';\n\n@UseGuards(ThrottlerGuard)\n@Post('login')\nasync login(@Body() dto: LoginDto) { ... }\n```",
        references: ["https://owasp.org/www-community/attacks/Brute_force_attack"],
        createdAt: /* @__PURE__ */ new Date()
      });
    }
  }
};

// ../agents/headers/dist/index.js
function parse(policy) {
  const map = /* @__PURE__ */ new Map();
  for (const part of policy.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const [name, ...vals] = trimmed.split(/\s+/);
    if (name) map.set(name.toLowerCase(), vals.map((v) => v.toLowerCase()));
  }
  return map;
}
function analyzeCsp(policy) {
  const d = parse(policy);
  const issues = [];
  const scriptSrc = d.get("script-src") ?? d.get("default-src");
  const styleSrc = d.get("style-src") ?? d.get("default-src");
  const has = (dir) => d.has(dir);
  if (scriptSrc?.includes("'unsafe-inline'") && !scriptSrc.some((v) => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
    issues.push({
      rule: "csp-unsafe-inline-script",
      severity: "high",
      title: "CSP com 'unsafe-inline' em script-src",
      detail: "'unsafe-inline' autoriza QUALQUER script inline \u2014 inclusive o injetado por XSS. Isso anula a principal prote\xE7\xE3o do CSP: o header existe, mas contra XSS n\xE3o vale quase nada.",
      recommendation: "Remova 'unsafe-inline' de script-src e use nonce por request ou hash dos scripts inline (com 'strict-dynamic')."
    });
  }
  if (scriptSrc?.includes("'unsafe-eval'")) {
    issues.push({
      rule: "csp-unsafe-eval",
      severity: "medium",
      title: "CSP com 'unsafe-eval' em script-src",
      detail: "'unsafe-eval' reabre eval()/new Function()/setTimeout(string) \u2014 amplia a superf\xEDcie de XSS.",
      recommendation: "Remova 'unsafe-eval' e refatore o c\xF3digo que depende de eval/Function din\xE2micos."
    });
  }
  if (!has("script-src") && !has("default-src")) {
    issues.push({
      rule: "csp-no-script-src",
      severity: "medium",
      title: "CSP sem script-src nem default-src",
      detail: "Sem script-src (nem default-src como fallback), a origem dos scripts n\xE3o \xE9 restringida pela policy.",
      recommendation: "Defina script-src 'self' (+ nonce/hash p/ inline) ou ao menos um default-src 'self'."
    });
  }
  if (scriptSrc && (scriptSrc.includes("*") || scriptSrc.includes("https:") || scriptSrc.includes("http:"))) {
    issues.push({
      rule: "csp-broad-script-src",
      severity: "medium",
      title: "CSP com script-src muito amplo (* / https:)",
      detail: "Permitir '*', 'https:' ou 'http:' em script-src deixa carregar script de quase qualquer origem \u2014 enfraquece muito a prote\xE7\xE3o.",
      recommendation: "Liste apenas as origens confi\xE1veis; prefira nonce/hash + strict-dynamic a curingas."
    });
  }
  if (!has("default-src")) {
    issues.push({
      rule: "csp-no-default-src",
      severity: "low",
      title: "CSP sem default-src",
      detail: "Sem default-src, diretivas n\xE3o declaradas (img-src, connect-src, font-src\u2026) n\xE3o t\xEAm fallback restritivo.",
      recommendation: "Adicione default-src 'self' como base e sobreponha s\xF3 o necess\xE1rio."
    });
  }
  const objectSrc = d.get("object-src");
  if (!objectSrc || !objectSrc.includes("'none'")) {
    issues.push({
      rule: "csp-object-src",
      severity: "low",
      title: "CSP sem object-src 'none'",
      detail: "object-src 'none' bloqueia <object>/<embed>/<applet> \u2014 vetores legados de execu\xE7\xE3o de conte\xFAdo.",
      recommendation: "Adicione object-src 'none'."
    });
  }
  if (!has("frame-ancestors")) {
    issues.push({
      rule: "csp-no-frame-ancestors",
      severity: "low",
      title: "CSP sem frame-ancestors",
      detail: "Sem frame-ancestors, a p\xE1gina pode ser embutida em <iframe> por qualquer origem \u2014 vetor de clickjacking (UI redress). frame-ancestors n\xE3o herda de default-src.",
      recommendation: "Adicione frame-ancestors 'none' (ou 'self'/origens confi\xE1veis). \xC9 o substituto moderno do X-Frame-Options."
    });
  }
  if (!has("form-action")) {
    issues.push({
      rule: "csp-no-form-action",
      severity: "low",
      title: "CSP sem form-action",
      detail: "Sem form-action, um <form> injetado (via XSS/HTML injection) pode enviar dados/credenciais para uma origem externa. Tamb\xE9m n\xE3o herda de default-src.",
      recommendation: "Adicione form-action 'self' (+ origens de checkout/SSO que precisem receber POST)."
    });
  }
  if (!has("base-uri")) {
    issues.push({
      rule: "csp-no-base-uri",
      severity: "low",
      title: "CSP sem base-uri",
      detail: "Sem base-uri 'self', uma tag <base> injetada pode redirecionar todas as URLs relativas (roubo de recursos/scripts).",
      recommendation: "Adicione base-uri 'self'."
    });
  }
  if (styleSrc?.includes("'unsafe-inline'") && !styleSrc.some((v) => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
    issues.push({
      rule: "csp-unsafe-inline-style",
      severity: "info",
      title: "CSP com 'unsafe-inline' em style-src",
      detail: "Menor risco que em scripts, mas permite CSS injetado (UI redress/exfiltra\xE7\xE3o via seletores). Informativo.",
      recommendation: "Prefira nonce/hash para estilos inline quando vi\xE1vel."
    });
  }
  return issues;
}
var tokens = (v) => v.split(",").map((s) => s.trim()).filter(Boolean);
var KNOWN_CDN_SERVERS = ["cloudflare", "vercel", "fastly", "akamai", "netlify", "awselb", "amazon", "nginx/"];
function isKnownCdn(serverValue) {
  const lower = serverValue.toLowerCase();
  return KNOWN_CDN_SERVERS.some((cdn) => lower.includes(cdn));
}
function hasVersionToken(value) {
  return /\/\s*\d/.test(value);
}
function requiredHeaderRec(headerName, stack) {
  const has = (s) => stack.some((t) => t.toLowerCase() === s);
  if (has("nextjs")) {
    return `Adicione o header \`${headerName}\` via \`next.config.js\`:
\`\`\`js
// next.config.js
module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: '${headerName}', value: '<valor recomendado>' }] }]
  },
}
\`\`\``;
  }
  if (has("nestjs") || has("nodejs") || has("express")) {
    if (headerName === "permissions-policy") {
      return `Adicione o header \`permissions-policy\` explicitamente \u2014 helmet **n\xE3o** o define por padr\xE3o:
\`\`\`typescript
app.use(helmet());
app.use((_req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
\`\`\``;
    }
    return `Adicione o header \`${headerName}\` via helmet:
\`\`\`typescript
app.use(helmet()); // inclui ${headerName} automaticamente
\`\`\``;
  }
  return `Configure seu servidor/proxy para enviar o header \`${headerName}\` com o valor recomendado pela OWASP Secure Headers Project.`;
}
function xPoweredByRec(stack) {
  const has = (s) => stack.some((t) => t.toLowerCase() === s);
  if (has("nextjs")) {
    return `Desative o \`X-Powered-By\` em \`next.config.js\`:
\`\`\`js
// next.config.js
module.exports = { poweredByHeader: false }
\`\`\``;
  }
  if (has("nestjs") || has("nodejs") || has("express")) {
    return `Desative o \`X-Powered-By\` no Express/NestJS:
\`\`\`typescript
app.disable('x-powered-by');
\`\`\``;
  }
  return `Configure seu servidor/proxy para omitir o header \`X-Powered-By\` nas respostas HTTP.`;
}
function serverHeaderRec(serverValue, stack) {
  if (isKnownCdn(serverValue)) {
    return `O valor \`${serverValue}\` \xE9 definido pelo CDN/hosting provider e **n\xE3o pode ser removido na origem**. \xC9 controlado pela infraestrutura (Cloudflare, Vercel, etc.). Considere configurar regras de transforma\xE7\xE3o de headers no painel do seu CDN para ocultar ou substituir o valor, se necess\xE1rio.`;
  }
  const has = (s) => stack.some((t) => t.toLowerCase() === s);
  if (has("nestjs") || has("nodejs") || has("express")) {
    return `O header \`server\` \xE9 definido pelo servidor web/proxy (nginx, Apache), n\xE3o pelo Node.js. Para ocultar a vers\xE3o no nginx use \`server_tokens off;\` em \`nginx.conf\`. Para remo\xE7\xE3o completa do header instale o m\xF3dulo \`headers-more-nginx-module\` e use \`more_clear_headers Server;\`.`;
  }
  if (has("nextjs")) {
    return `O header \`server\` \xE9 definido pelo servidor web/proxy (nginx, Apache ou o servidor Next.js). Para ocultar a vers\xE3o no nginx use \`server_tokens off;\` em \`nginx.conf\`. Para remo\xE7\xE3o completa instale \`headers-more-nginx-module\` e use \`more_clear_headers Server;\`.`;
  }
  return `O header \`server\` \xE9 definido pelo servidor web/proxy (nginx, Apache, etc.), n\xE3o pela aplica\xE7\xE3o. Para ocultar a vers\xE3o no nginx use \`server_tokens off;\` em \`nginx.conf\`. Para remo\xE7\xE3o completa instale \`headers-more-nginx-module\` e use \`more_clear_headers Server;\`.`;
}
var REQUIRED_HEADERS = [
  {
    name: "strict-transport-security",
    severity: "high",
    validate: (v) => v.includes("max-age="),
    message: "HSTS ausente ou sem max-age"
  },
  {
    name: "x-content-type-options",
    severity: "medium",
    validate: (v) => {
      const t = tokens(v);
      return t.length > 0 && t.every((x) => x.toLowerCase() === "nosniff");
    },
    message: "X-Content-Type-Options ausente ou incorreto"
  },
  {
    name: "x-frame-options",
    severity: "medium",
    validate: (v) => {
      const t = tokens(v);
      return t.length > 0 && t.every((x) => x.toUpperCase() === "DENY" || x.toUpperCase() === "SAMEORIGIN");
    },
    message: "X-Frame-Options ausente ou incorreto"
  },
  {
    name: "referrer-policy",
    severity: "low",
    validate: (v) => v.length > 0,
    message: "Referrer-Policy ausente"
  },
  {
    name: "permissions-policy",
    severity: "low",
    validate: (v) => v.length > 0,
    message: "Permissions-Policy ausente"
  }
];
var HeadersAgent = class {
  /**
   * `createClient` permite injetar um cliente HTTP endurecido (ex.: o
   * `@fracta/web-scan` injeta um cliente com dispatcher que valida o IP em
   * cada conexão, fechando SSRF por redirect). Sem ele, usa o cliente padrão
   * (comportamento histórico do CLI).
   */
  constructor(opts = {}) {
    this.opts = opts;
  }
  opts;
  name = "HEADERS Agent";
  category = "security";
  concurrency = 1;
  timeoutMs = 15e3;
  async run(scope) {
    const findings = [];
    const { target } = scope;
    const client = this.opts.createClient?.(target.url) ?? new FractaHttpClient(target.url);
    let res;
    try {
      res = await client.request("/", { timeoutMs: this.timeoutMs });
    } catch (err) {
      throw new SkippedCheck(`n\xE3o foi poss\xEDvel conectar a ${target.url}: ${String(err)}`);
    }
    const headers = res.headers;
    const mk = (rule, severity, title, description, recommendation, extra = {}) => ({
      id: stableFindingId({ saas: target.name, camada: this.category, rule, location: target.url }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity,
      title,
      description,
      recommendation,
      references: ["https://owasp.org/www-project-secure-headers/"],
      createdAt: /* @__PURE__ */ new Date(),
      ...extra
    });
    for (const rule of REQUIRED_HEADERS) {
      const value = headers[rule.name] ?? "";
      if (!value || !rule.validate(value)) {
        findings.push(mk(
          `header-missing:${rule.name}`,
          rule.severity,
          `Security header ausente: ${rule.name}`,
          rule.message,
          requiredHeaderRec(rule.name, target.stack ?? [])
        ));
      }
    }
    const csp = (headers["content-security-policy"] ?? "").trim();
    const cspReportOnly = (headers["content-security-policy-report-only"] ?? "").trim();
    if (!csp && !cspReportOnly) {
      findings.push(mk(
        "csp-missing",
        "low",
        "Content-Security-Policy ausente",
        "Sem CSP, o navegador n\xE3o tem uma pol\xEDtica para bloquear scripts/recursos injetados \u2014 \xE9 a defesa mais forte contra XSS. Aus\xEAncia n\xE3o \xE9 um buraco direto, mas \xE9 a camada que mais reduz o impacto de um XSS.",
        "Adicione um CSP. Comece em Report-Only para n\xE3o quebrar, com baseline: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'. Em Next.js, use nonce por request.",
        { confidence: "high", proposedFix: {
          description: "Baseline (endure\xE7a conforme o app):  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none' . Suba primeiro como Content-Security-Policy-Report-Only para observar viola\xE7\xF5es sem quebrar, depois troque para enforcement.",
          riskOfApplying: "PROPOSTA \u2014 um CSP estrito pode quebrar scripts/estilos inline leg\xEDtimos. Por isso: Report-Only primeiro, ajuste, e s\xF3 ent\xE3o imponha. Em Next.js use nonce (sen\xE3o a hidrata\xE7\xE3o quebra)."
        } }
      ));
    } else if (!csp && cspReportOnly) {
      findings.push(mk(
        "csp-report-only",
        "low",
        "CSP presente apenas em Report-Only (n\xE3o bloqueia)",
        "H\xE1 um Content-Security-Policy-Report-Only, mas nenhum CSP em modo de imposi\xE7\xE3o. Report-Only s\xF3 coleta viola\xE7\xF5es \u2014 N\xC3O bloqueia scripts injetados.",
        "Depois de validar as viola\xE7\xF5es do Report-Only, publique a mesma policy como Content-Security-Policy (enforcement).",
        { confidence: "high" }
      ));
    } else {
      for (const issue of analyzeCsp(csp)) {
        findings.push(mk(
          issue.rule,
          issue.severity,
          issue.title,
          issue.detail,
          issue.recommendation,
          { confidence: "high", evidence: `content-security-policy: ${csp.length > 220 ? csp.slice(0, 220) + "\u2026" : csp}` }
        ));
      }
    }
    if (headers["x-powered-by"]) {
      const v = headers["x-powered-by"];
      findings.push(mk(
        "header-forbidden:x-powered-by",
        "low",
        "Header proibido presente: x-powered-by",
        "X-Powered-By exp\xF5e o framework/vers\xE3o",
        xPoweredByRec(target.stack ?? []),
        { evidence: `x-powered-by: ${v}` }
      ));
    }
    if (headers["server"]) {
      const v = headers["server"];
      const versioned = hasVersionToken(v);
      findings.push(mk(
        "header-forbidden:server",
        versioned ? "low" : "info",
        versioned ? "Server header exp\xF5e a vers\xE3o do servidor: server" : "Server header presente (informativo): server",
        versioned ? "O header `server` revela a vers\xE3o do servidor web (facilita fingerprinting de vulnerabilidades conhecidas)." : "Header `server` presente, sem vers\xE3o exposta \u2014 informativo e n\xE3o-acion\xE1vel (definido por CDN/proxy, n\xE3o remov\xEDvel na origem).",
        serverHeaderRec(v, target.stack ?? []),
        { evidence: `server: ${v}` }
      ));
    }
    await this.testCors(scope, client, findings, mk);
    return findings;
  }
  async testCors(scope, client, findings, mk) {
    const origins = ["https://evil.com", "null"];
    for (const origin of origins) {
      try {
        const res = await client.request("/", {
          headers: { Origin: origin },
          timeoutMs: 5e3
        });
        const acao = res.headers["access-control-allow-origin"] ?? "";
        if (acao === "*") {
          findings.push(mk(
            "cors-wildcard",
            "high",
            "CORS wildcard: Access-Control-Allow-Origin: *",
            "O servidor aceita requisi\xE7\xF5es cross-origin de qualquer origem.",
            "Configure CORS para aceitar apenas origens conhecidas:\n```typescript\napp.enableCors({ origin: ['https://meuapp.com.br'] });\n```",
            {
              evidence: `Origin: ${origin} \u2192 Access-Control-Allow-Origin: *`,
              references: ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"]
            }
          ));
          break;
        } else if (acao === origin && origin !== "null") {
          findings.push(mk(
            "cors-reflect",
            "medium",
            "CORS reflete origem arbitr\xE1ria",
            "O servidor reflete qualquer origem recebida no Access-Control-Allow-Origin.",
            "Use uma allowlist expl\xEDcita de origens no CORS config.",
            {
              evidence: `Origin: ${origin} \u2192 Access-Control-Allow-Origin: ${acao}`,
              references: ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"]
            }
          ));
        }
      } catch {
      }
    }
  }
};

// ../agents/dns/dist/index.js
import { resolveTxt as dnsResolveTxt, resolveMx as dnsResolveMx } from "dns/promises";
import { isIP } from "net";
var defaultResolver = {
  resolveTxt: (n) => dnsResolveTxt(n),
  resolveMx: (n) => dnsResolveMx(n)
};
var joinTxt = (chunks) => chunks.join("");
function parseSpf(records) {
  const rec = records.map(joinTxt).find((r) => /^v=spf1\b/i.test(r.trim()));
  if (!rec) return { present: false };
  const m = rec.match(/([-~?+])all\b/i);
  const map = { "-": "fail", "~": "softfail", "?": "neutral", "+": "pass" };
  return { present: true, record: rec, all: m ? map[m[1]] : "none" };
}
function parseDmarc(records) {
  const rec = records.map(joinTxt).find((r) => /^v=dmarc1\b/i.test(r.trim()));
  if (!rec) return { present: false };
  const p = rec.match(/\bp\s*=\s*(none|quarantine|reject)\b/i);
  const pct = rec.match(/\bpct\s*=\s*(\d+)\b/i);
  return {
    present: true,
    record: rec,
    policy: p?.[1]?.toLowerCase() ?? "none",
    pct: pct ? Number(pct[1]) : void 0
  };
}
var DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "k1", "resend", "s1", "dkim"];
var TWO_LEVEL_TLD = /* @__PURE__ */ new Set(["com.br", "adv.br", "net.br", "org.br", "gov.br", "eng.br", "co.uk", "com.au"]);
function registrableDomain(host) {
  const labels = host.replace(/^www\./i, "").replace(/\.$/, "").toLowerCase().split(".");
  if (labels.length <= 2) return labels.join(".");
  const last2 = labels.slice(-2).join(".");
  return TWO_LEVEL_TLD.has(last2) ? labels.slice(-3).join(".") : last2;
}
async function analyzeEmailDns(domain, resolver = defaultResolver) {
  const safe = async (p, fb) => {
    try {
      return await p;
    } catch {
      return fb;
    }
  };
  const [txt, mx, dmarcTxt] = await Promise.all([
    safe(resolver.resolveTxt(domain), []),
    safe(resolver.resolveMx(domain), []),
    safe(resolver.resolveTxt(`_dmarc.${domain}`), [])
  ]);
  const probes = await Promise.all(
    DKIM_SELECTORS.map(async (sel) => {
      const r = await safe(resolver.resolveTxt(`${sel}._domainkey.${domain}`), []);
      const has = r.map(joinTxt).some((x) => /v=dkim1|k=rsa|(^|;)\s*p=/i.test(x));
      return has ? sel : null;
    })
  );
  return {
    domain,
    hasMx: mx.length > 0,
    spf: parseSpf(txt),
    dmarc: parseDmarc(dmarcTxt),
    dkim: { probed: DKIM_SELECTORS, found: probes.filter((s) => s !== null) }
  };
}
var REFS = ["https://datatracker.ietf.org/doc/html/rfc7208", "https://datatracker.ietf.org/doc/html/rfc7489"];
var DnsAgent = class {
  constructor(resolver = defaultResolver) {
    this.resolver = resolver;
  }
  resolver;
  name = "DNS Agent";
  category = "security";
  concurrency = 1;
  timeoutMs = 15e3;
  async run(scope) {
    let host;
    try {
      host = new URL(scope.target.url).hostname;
    } catch {
      return [];
    }
    if (isIP(host) || !host.includes(".")) return [];
    const domain = registrableDomain(host);
    const r = await analyzeEmailDns(domain, this.resolver);
    return this.toFindings(scope, r);
  }
  make(scope, rule, severity, title, description, recommendation, proposedFix, evidence) {
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity,
      confidence: "high",
      // registro DNS é fato
      title,
      description,
      recommendation,
      references: REFS,
      createdAt: /* @__PURE__ */ new Date(),
      ...proposedFix ? { proposedFix } : {},
      ...evidence ? { evidence } : {}
    };
  }
  toFindings(scope, r) {
    const out = [];
    const d = r.domain;
    const missSev = r.hasMx ? "medium" : "low";
    const noMxHint = r.hasMx ? "" : ' (o dom\xEDnio n\xE3o tem MX \u2014 mesmo assim, o NOME pode ser forjado; o ideal \xE9 travar com "-all"/p=reject).';
    if (!r.spf.present) {
      out.push(this.make(
        scope,
        "dns-spf-missing",
        missSev,
        `Sem registro SPF em ${d}`,
        `O dom\xEDnio ${d} n\xE3o tem registro SPF (TXT v=spf1). Sem SPF, \xE9 mais f\xE1cil forjar e-mails com o seu dom\xEDnio (phishing) \u2014 receptores n\xE3o sabem quais servidores podem enviar em seu nome.${noMxHint}`,
        'Publique um registro SPF listando seus servidores de envio e termine com "-all" (hardfail). Se o dom\xEDnio n\xE3o envia e-mail, use apenas "v=spf1 -all".',
        {
          description: `Adicione um TXT no host "@" de ${d}: se N\xC3O envia e-mail, use exatamente  v=spf1 -all . Se envia, liste os remetentes e termine com -all, ex.:  v=spf1 include:_spf.resend.com -all .`,
          riskOfApplying: 'PROPOSTA \u2014 n\xE3o aplicada. Se voc\xEA envia e-mail, liste TODOS os remetentes (provedor transacional, ERP, etc.) ANTES de "-all", sen\xE3o e-mail leg\xEDtimo \xE9 rejeitado.'
        }
      ));
    } else if (r.spf.all === "pass") {
      out.push(this.make(
        scope,
        "dns-spf-permissive",
        "high",
        `SPF permissivo (+all) em ${d}`,
        `O SPF de ${d} termina com "+all", que autoriza QUALQUER servidor a enviar e-mail em nome do dom\xEDnio \u2014 equivale a n\xE3o ter prote\xE7\xE3o e facilita spoofing.`,
        'Troque "+all" por "-all" (hardfail), listando apenas os servidores de envio leg\xEDtimos.',
        {
          description: `No TXT do host "@" de ${d}, troque o " +all " final por " -all ", mantendo os includes dos seus remetentes leg\xEDtimos.`,
          riskOfApplying: "PROPOSTA \u2014 confirme que todos os remetentes est\xE3o nos includes antes de trocar por -all."
        },
        r.spf.record
      ));
    } else if (r.spf.all === "neutral") {
      out.push(this.make(
        scope,
        "dns-spf-neutral",
        "low",
        `SPF neutro (?all) em ${d}`,
        `O SPF de ${d} usa "?all" (neutral): n\xE3o afirma nada sobre remetentes n\xE3o listados, ent\xE3o n\xE3o protege efetivamente contra spoofing.`,
        'Use "-all" (hardfail) ou ao menos "~all" (softfail) em vez de "?all".',
        {
          description: `No TXT do host "@" de ${d}, troque " ?all " por " -all " (mantendo os includes dos remetentes leg\xEDtimos).`,
          riskOfApplying: 'PROPOSTA \u2014 confirme os remetentes antes de -all; se preferir cauteloso, use "~all".'
        },
        r.spf.record
      ));
    }
    if (!r.dmarc.present) {
      out.push(this.make(
        scope,
        "dns-dmarc-missing",
        missSev,
        `Sem registro DMARC em ${d}`,
        `O dom\xEDnio ${d} n\xE3o tem DMARC (TXT em _dmarc.${d}). Sem DMARC, mesmo com SPF/DKIM os receptores n\xE3o t\xEAm uma POL\xCDTICA para barrar e-mails forjados, e voc\xEA n\xE3o recebe relat\xF3rios de abuso.${noMxHint}`,
        "Publique um DMARC come\xE7ando por p=none (monitorar) e evolua para p=quarantine e p=reject; use rua= para receber relat\xF3rios.",
        {
          description: r.hasMx ? `Adicione um TXT no host "_dmarc.${d}":  v=DMARC1; p=none; rua=mailto:dmarc@${d}; fo=1  (monitora, n\xE3o bloqueia). Ap\xF3s validar os relat\xF3rios, evolua para p=quarantine e depois p=reject.` : `Adicione um TXT no host "_dmarc.${d}":  v=DMARC1; p=reject  (o dom\xEDnio n\xE3o envia e-mail \u2014 reject \xE9 seguro e trava spoofing de imediato).`,
          riskOfApplying: "PROPOSTA \u2014 p=none N\xC3O afeta entrega (s\xF3 monitora). S\xF3 suba para quarantine/reject ap\xF3s confirmar que SPF/DKIM alinham no e-mail leg\xEDtimo."
        }
      ));
    } else if (r.dmarc.policy === "none") {
      out.push(this.make(
        scope,
        "dns-dmarc-none",
        "low",
        `DMARC em modo monitor (p=none) em ${d}`,
        `O DMARC de ${d} est\xE1 com p=none: s\xF3 monitora, N\xC3O instrui os receptores a barrar e-mail forjado. \xC9 o primeiro passo, mas n\xE3o protege contra spoofing enquanto n\xE3o endurecer.`,
        "Ap\xF3s validar os relat\xF3rios, evolua para p=quarantine e depois p=reject.",
        {
          description: `No TXT "_dmarc.${d}", troque  p=none  por  p=quarantine  (e depois  p=reject ), mantendo o rua=.`,
          riskOfApplying: "PROPOSTA \u2014 suba a r\xE9gua s\xF3 ap\xF3s os relat\xF3rios rua= mostrarem que o e-mail leg\xEDtimo passa."
        },
        r.dmarc.record
      ));
    }
    if (r.dkim.found.length === 0 && r.hasMx) {
      out.push(this.make(
        scope,
        "dns-dkim-not-found",
        "info",
        `DKIM n\xE3o detectado nos seletores comuns em ${d}`,
        `O dom\xEDnio ${d} recebe e-mail (tem MX) mas n\xE3o encontrei DKIM nos seletores comuns testados (${r.dkim.probed.join(", ")}). Best-effort: voc\xEA pode usar um seletor diferente \u2014 isto \xE9 informativo, n\xE3o penaliza.`,
        "Confirme que o e-mail transacional assina com DKIM (o seletor correto do seu provedor).",
        {
          description: `Ative DKIM no seu provedor de e-mail transacional \u2014 ele fornece o seletor e a chave p\xFAblica a publicar como TXT em  <seletor>._domainkey.${d} .`,
          riskOfApplying: "PROPOSTA \u2014 configura\xE7\xE3o no provedor; adiciona assinatura, sem quebrar entrega. Confirme o seletor correto."
        }
      ));
    }
    return out;
  }
};

// ../agents/idor/dist/index.js
var CATEGORY = "security";
var AGENT = "IDOR Agent";
var REFS2 = [
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
      references: REFS2,
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
      references: REFS2,
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
    references: REFS2,
    createdAt: /* @__PURE__ */ new Date()
  }];
}
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
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "idor-auth-not-configured" }),
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
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-direct-access:${path}`, location: path }),
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
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-error-500:${path}`, location: path }),
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
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-crosstenant-setup:${title}` }),
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
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `idor-enumeration:${basePath}`, location: basePath }),
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

// ../agents/docs/dist/index.js
import { readdir, readFile, stat } from "fs/promises";
import { join, relative } from "path";
var IGNORE_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", "dist", ".next", "coverage", ".turbo", "__tests__", "fracta-reports", ".worktrees", ".claude"]);
var LEGACY_PATTERNS = /old|legado|legacy|deprecated|backup|v1\.|_old\.|antigo/i;
var MS_IN_DAY = 864e5;
var TODO_MARKER = /\b(TODO|FIXME|XXX|HACK)\b/;
var DocsAgent = class {
  /**
   * `explicitRepoPath` é um override (ex.: o comando `fracta docs --docs-path`).
   * No `scan`, fica indefinido e o repo vem de `target.repoPath`. SEM nenhum dos
   * dois, o agente PULA (SkippedCheck) — jamais cai no `process.cwd()`, que
   * escanearia o próprio Fracta e produziria achados desonestos.
   */
  constructor(explicitRepoPath) {
    this.explicitRepoPath = explicitRepoPath;
  }
  explicitRepoPath;
  name = "DOCS Agent";
  category = "docs";
  concurrency = 1;
  timeoutMs = 6e4;
  async run(scope) {
    const findings = [];
    const repoPath = this.explicitRepoPath ?? scope.target.repoPath;
    if (!repoPath) {
      throw new SkippedCheck(
        "DOCS Agent: sem repoPath no target \u2014 defina `repoPath` para auditar a documenta\xE7\xE3o do reposit\xF3rio."
      );
    }
    try {
      const files = await this.collectMarkdownFiles(repoPath);
      if (files.length === 0) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "docs-none" }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "info",
          title: "Nenhum arquivo .md encontrado",
          description: `Nenhum arquivo Markdown encontrado em ${repoPath}`,
          recommendation: "Adicione documenta\xE7\xE3o Markdown ao reposit\xF3rio.",
          createdAt: /* @__PURE__ */ new Date()
        });
        return findings;
      }
      const h1Titles = /* @__PURE__ */ new Map();
      for (const file of files) {
        await this.auditFile(scope, file, findings, h1Titles);
      }
      this.checkDuplicateTitles(scope, h1Titles, findings);
    } catch (err) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "docs-read-error" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "info",
        title: "DOCS Agent \u2014 erro ao ler reposit\xF3rio",
        description: `Erro ao escanear ${repoPath}: ${String(err)}`,
        recommendation: "Verifique se o caminho do reposit\xF3rio est\xE1 correto.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    return findings;
  }
  async auditFile(scope, file, findings, h1Titles) {
    const ageMs = Date.now() - file.modifiedAt.getTime();
    const ageDays = Math.floor(ageMs / MS_IN_DAY);
    if (ageDays > 180) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-stale:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "medium",
        title: `Documenta\xE7\xE3o obsoleta: ${file.relativePath}`,
        description: `Arquivo n\xE3o modificado h\xE1 ${ageDays} dias (>180 dias).`,
        endpoint: file.relativePath,
        recommendation: "Revise e atualize o arquivo ou adicione uma nota de deprecia\xE7\xE3o no topo.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    if (LEGACY_PATTERNS.test(file.relativePath)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-legacy-name:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "medium",
        title: `Arquivo com nome legado: ${file.relativePath}`,
        description: "Nome do arquivo sugere conte\xFAdo legado, backup ou depreciado.",
        endpoint: file.relativePath,
        recommendation: "Remova o arquivo se for obsoleto, ou renomeie e documente o status atual.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    if (TODO_MARKER.test(file.content)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-todo:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "low",
        title: `TODOs n\xE3o resolvidos: ${file.relativePath}`,
        description: "Arquivo cont\xE9m marca\xE7\xF5es TODO/FIXME/XXX/HACK indicando documenta\xE7\xE3o incompleta.",
        endpoint: file.relativePath,
        recommendation: "Resolva os TODOs ou abra issues para rastre\xE1-los.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    const v1Matches = (file.content.match(/(?<![/\w.])v[01](?![/\w.-])/gi) ?? []).length;
    if (v1Matches > 2) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-legacy-version-refs:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "medium",
        title: `Refer\xEAncias a vers\xF5es legadas: ${file.relativePath}`,
        description: `${v1Matches} refer\xEAncias a v0/v1 encontradas. Pode indicar documenta\xE7\xE3o desatualizada.`,
        endpoint: file.relativePath,
        recommendation: "Verifique se as refer\xEAncias a vers\xF5es antigas s\xE3o intencionais ou precisam ser atualizadas.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    const h1Match = file.content.match(/^#\s+(.+)$/m);
    if (h1Match) {
      const title = h1Match[1].trim();
      const existing = h1Titles.get(title) ?? [];
      h1Titles.set(title, [...existing, file.relativePath]);
    }
  }
  checkDuplicateTitles(scope, h1Titles, findings) {
    for (const [title, paths] of h1Titles) {
      if (paths.length > 1) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-duplicate-h1:${title}` }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "low",
          title: `T\xEDtulo H1 duplicado: "${title}"`,
          description: `O mesmo t\xEDtulo H1 aparece em ${paths.length} arquivos: ${paths.join(", ")}`,
          recommendation: "Use t\xEDtulos \xFAnicos para facilitar navega\xE7\xE3o e indexa\xE7\xE3o.",
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    }
  }
  async collectMarkdownFiles(dir) {
    const files = [];
    await this.walkDir(dir, dir, files);
    return files;
  }
  async walkDir(dir, baseDir, files) {
    let entries;
    try {
      entries = await readdir(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue;
      const fullPath = join(dir, entry);
      try {
        const info = await stat(fullPath);
        if (info.isDirectory()) {
          await this.walkDir(fullPath, baseDir, files);
        } else if (entry.endsWith(".md")) {
          const content = await readFile(fullPath, "utf-8");
          files.push({
            path: fullPath,
            content,
            modifiedAt: info.mtime,
            relativePath: relative(baseDir, fullPath).replace(/\\/g, "/")
          });
        }
      } catch {
      }
    }
  }
};

// ../agents/tenant/dist/index.js
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
function getIdsForDepth2(depth) {
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
    const ids = getIdsForDepth2(scope.depth);
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

// ../agents/race/dist/index.js
import { randomUUID } from "crypto";
var PROBES = [
  { path: "/api/coupons/redeem", body: { code: "FRACTA-TEST" }, description: "resgate de cupom" },
  { path: "/api/cupons/aplicar", body: { codigo: "FRACTA-TEST" }, description: "aplica\xE7\xE3o de cupom" },
  { path: "/api/vouchers/redeem", body: { code: "FRACTA-TEST" }, description: "resgate de voucher" },
  { path: "/api/invites/accept", body: { token: "fracta-test-token" }, description: "aceite de convite" },
  { path: "/api/votes", body: { optionId: 1 }, description: "vota\xE7\xE3o" },
  { path: "/api/likes", body: { targetId: 1 }, description: "like/curtida" },
  { path: "/api/withdrawals", body: { amount: 1 }, description: "saque" },
  { path: "/api/transfers", body: { amount: 1, to: "test" }, description: "transfer\xEAncia" }
];
function concurrentCountFor(depth) {
  if (depth === "paranoid") return 20;
  if (depth === "full") return 10;
  return 5;
}
function loginPathCandidates(authEndpoint) {
  const defaults = ["/api/auth/login", "/auth/login", "/api/login", "/login"];
  if (authEndpoint) return [authEndpoint, ...defaults.filter((p) => p !== authEndpoint)];
  return defaults;
}
var RaceAgent = class {
  name = "RACE Agent";
  category = "security";
  concurrency = 1;
  timeoutMs = 12e4;
  async run(scope) {
    const findings = [];
    const { target, depth } = scope;
    if (depth === "quick") {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "race-skipped:quick" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "info",
        title: "RACE Agent \u2014 depth=quick pula testes destrutivos",
        description: "Testes de race condition envolvem rajadas de POSTs concorrentes. Em quick scan eles s\xE3o pulados para n\xE3o impactar o staging.",
        recommendation: "Use --depth full ou --depth paranoid para rodar RACE Agent completo.",
        createdAt: /* @__PURE__ */ new Date()
      });
      await this.runTimingProbe(scope, findings);
      return findings;
    }
    let client;
    if (target.auth?.credentials?.email && target.auth?.credentials?.password && target.auth?.endpoint) {
      try {
        const result = await FractaHttpClient.withJwt(
          target.url,
          target.auth.endpoint,
          { email: target.auth.credentials.email, password: target.auth.credentials.password }
        );
        client = result.client;
      } catch {
        client = new FractaHttpClient(target.url);
      }
    } else {
      client = new FractaHttpClient(target.url);
    }
    const ignore = target.ignore ?? [];
    const burst = concurrentCountFor(depth);
    for (const probe of PROBES) {
      if (ignore.some((i) => probe.path.startsWith(i))) continue;
      await this.runBurst(scope, client, probe, burst, findings);
    }
    await this.runTimingProbe(scope, findings);
    return findings;
  }
  async runBurst(scope, client, probe, burst, findings) {
    const responses = await Promise.allSettled(
      Array.from(
        { length: burst },
        () => client.request(probe.path, { method: "POST", body: probe.body, timeoutMs: 5e3 })
      )
    );
    let successes = 0;
    let notFound = 0;
    for (const r of responses) {
      if (r.status === "fulfilled") {
        if (r.value.status >= 200 && r.value.status < 300) successes++;
        else if (r.value.status === 404) notFound++;
      }
    }
    if (notFound >= Math.ceil(burst * 0.6)) return;
    if (successes >= 2) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `race-condition:${probe.path}`, location: probe.path }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "high",
        title: `Race condition em ${probe.path} (${probe.description})`,
        description: `Disparei ${burst} POSTs concorrentes em ${probe.path}; ${successes} responderam 2xx. A\xE7\xF5es que devem ser idempotentes (${probe.description}) n\xE3o devem aceitar m\xFAltiplas execu\xE7\xF5es simult\xE2neas.`,
        endpoint: probe.path,
        evidence: `POST x${burst} concorrentes \u2192 ${successes} sucessos / ${notFound} 404 / ${burst - successes - notFound} outros`,
        recommendation: "Use lock pessimista no banco ou idempotency keys:\n```typescript\nawait this.prisma.$transaction(async (tx) => {\n  const coupon = await tx.coupon.findUnique({\n    where: { code }, select: { id: true, redeemedAt: true },\n  });\n  if (coupon?.redeemedAt) throw new ConflictException();\n  await tx.coupon.update({\n    where: { id: coupon.id, redeemedAt: null },\n    data: { redeemedAt: new Date(), redeemedBy: userId },\n  });\n});\n```",
        references: [
          "https://owasp.org/www-community/vulnerabilities/Race_condition",
          "https://cwe.mitre.org/data/definitions/362.html"
        ],
        createdAt: /* @__PURE__ */ new Date()
      });
    }
  }
  async runTimingProbe(scope, findings) {
    const { target } = scope;
    if (!target.auth?.credentials?.email) return;
    const paths = loginPathCandidates(target.auth.endpoint);
    const baseClient = new FractaHttpClient(target.url);
    const samples = 5;
    for (const path of paths) {
      const validEmail = target.auth.credentials.email;
      const fakeEmail = `does-not-exist-${randomUUID().substring(0, 8)}@fracta.test`;
      const timesValid = await this.measureLogin(baseClient, path, validEmail, samples);
      const timesFake = await this.measureLogin(baseClient, path, fakeEmail, samples);
      if (timesValid.length < samples || timesFake.length < samples) continue;
      const avgValid = avg(timesValid);
      const avgFake = avg(timesFake);
      const delta = Math.abs(avgValid - avgFake);
      if (delta > 100) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `timing-attack:${path}`, location: path }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "medium",
          title: `Timing attack poss\xEDvel em ${path}: enumera\xE7\xE3o de usu\xE1rios`,
          description: `Login com email existente (${avgValid.toFixed(0)}ms) vs inexistente (${avgFake.toFixed(0)}ms) tem varia\xE7\xE3o de ${delta.toFixed(0)}ms \u2014 atacante consegue enumerar usu\xE1rios medindo o tempo de resposta.`,
          endpoint: path,
          evidence: `Avg v\xE1lido: ${avgValid.toFixed(0)}ms / Avg inexistente: ${avgFake.toFixed(0)}ms / \u0394=${delta.toFixed(0)}ms`,
          recommendation: "Sempre execute a verifica\xE7\xE3o de senha (bcrypt.compare) mesmo se o usu\xE1rio n\xE3o existir \u2014 compare contra um hash dummy fixo:\n```typescript\nconst DUMMY_HASH = '$2b$10$abcdefghijklmnopqrstuv';\nconst hash = user?.password ?? DUMMY_HASH;\nconst ok = await bcrypt.compare(password, hash);\nif (!user || !ok) throw new UnauthorizedException();\n```",
          references: [
            "https://owasp.org/www-community/attacks/Timing_attack",
            "https://cwe.mitre.org/data/definitions/208.html"
          ],
          createdAt: /* @__PURE__ */ new Date()
        });
        break;
      }
    }
  }
  async measureLogin(client, path, email, samples) {
    const times = [];
    for (let i = 0; i < samples; i++) {
      const start = performance.now();
      try {
        await client.request(path, {
          method: "POST",
          body: { email, password: "fracta-wrong-password-9999" },
          timeoutMs: 4e3
        });
        times.push(performance.now() - start);
      } catch {
      }
    }
    return times;
  }
};
function avg(nums) {
  return nums.reduce((s, n) => s + n, 0) / nums.length;
}

// ../agents/stripe/dist/index.js
import { createHmac } from "crypto";
var WEBHOOK_PATHS = [
  "/api/stripe/webhook",
  "/api/webhooks/stripe",
  "/api/webhook/stripe",
  "/webhooks/stripe",
  "/webhook/stripe",
  "/stripe/webhook",
  "/api/payments/webhook",
  "/api/billing/webhook"
];
var SAMPLE_EVENT = {
  id: "evt_fracta_test_00000000",
  object: "event",
  api_version: "2024-06-20",
  created: Math.floor(Date.now() / 1e3),
  type: "customer.subscription.created",
  data: {
    object: {
      id: "sub_fracta_test",
      object: "subscription",
      customer: "cus_fracta_test",
      status: "active"
    }
  },
  livemode: false,
  pending_webhooks: 1,
  request: { id: null, idempotency_key: null }
};
function buildSignature(payload, timestamp, secret) {
  const signed = `${timestamp}.${payload}`;
  const v1 = createHmac("sha256", secret).update(signed).digest("hex");
  return `t=${timestamp},v1=${v1}`;
}
var StripeAgent = class {
  name = "STRIPE Agent";
  category = "security";
  concurrency = 1;
  timeoutMs = 6e4;
  webhookSecret;
  constructor(options = {}) {
    this.webhookSecret = options.webhookSecret ?? process.env.STRIPE_WEBHOOK_SECRET;
  }
  async run(scope) {
    const findings = [];
    const { target } = scope;
    if (!target.stack?.includes("stripe")) {
      return findings;
    }
    const client = new FractaHttpClient(target.url);
    const ignore = target.ignore ?? [];
    const discovered = await this.discoverWebhookPaths(client, ignore);
    if (discovered.length === 0) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "stripe-no-webhook-discovered" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "info",
        title: "Stripe declarado em stack, mas nenhum endpoint de webhook descoberto",
        description: 'A stack declara "stripe" no targets.yaml mas nenhuma das rotas comuns de webhook respondeu. Confirme se h\xE1 webhook recebendo eventos Stripe.',
        recommendation: "Se o endpoint usa um path customizado, declare-o explicitamente para testes futuros. Caso ainda n\xE3o exista webhook, o m\xF3dulo de billing fica cego a falhas de pagamento.",
        createdAt: /* @__PURE__ */ new Date()
      });
      return findings;
    }
    for (const path of discovered) {
      await this.testEndpoint(scope, client, path, findings);
    }
    return findings;
  }
  async discoverWebhookPaths(client, ignore) {
    const found = [];
    for (const path of WEBHOOK_PATHS) {
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, {
          method: "POST",
          body: { ping: "fracta" },
          timeoutMs: 4e3
        });
        if (res.status !== 404) found.push(path);
      } catch {
      }
    }
    return found;
  }
  async testEndpoint(scope, client, path, findings) {
    const payload = JSON.stringify(SAMPLE_EVENT);
    const noSig = await this.safePost(client, path, payload, {});
    if (noSig && noSig.status >= 200 && noSig.status < 300) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `stripe-webhook-unsigned:${path}`, location: path }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "critical",
        title: `Webhook Stripe aceita POST sem assinatura: ${path}`,
        description: `${path} respondeu HTTP ${noSig.status} para um payload de evento Stripe sem o header Stripe-Signature. Atacante consegue forjar eventos (subscription.created, invoice.paid) e ativar assinaturas/cr\xE9ditos sem pagar.`,
        endpoint: path,
        evidence: `POST ${path} (sem Stripe-Signature) \u2192 HTTP ${noSig.status}`,
        recommendation: "Sempre valide a assinatura com stripe.webhooks.constructEvent antes de qualquer l\xF3gica de neg\xF3cio:\n```typescript\nconst event = stripe.webhooks.constructEvent(\n  req.rawBody,\n  req.headers['stripe-signature'],\n  process.env.STRIPE_WEBHOOK_SECRET,\n);\n```",
        references: [
          "https://docs.stripe.com/webhooks#verify-events",
          "https://cwe.mitre.org/data/definitions/345.html"
        ],
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    const fakeSig = await this.safePost(client, path, payload, {
      "Stripe-Signature": `t=${Math.floor(Date.now() / 1e3)},v1=0000000000000000000000000000000000000000000000000000000000000000`
    });
    if (fakeSig && fakeSig.status >= 200 && fakeSig.status < 300) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `stripe-webhook-badsig:${path}`, location: path }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "critical",
        title: `Webhook Stripe aceita assinatura inv\xE1lida: ${path}`,
        description: `${path} respondeu HTTP ${fakeSig.status} para Stripe-Signature claramente inv\xE1lido (v1=0...0). A valida\xE7\xE3o est\xE1 ausente ou quebrada.`,
        endpoint: path,
        evidence: `POST ${path} com Stripe-Signature=t=...,v1=00...00 \u2192 HTTP ${fakeSig.status}`,
        recommendation: "Use o SDK oficial do Stripe (stripe.webhooks.constructEvent) \u2014 implementa\xE7\xF5es manuais costumam falhar por usar compara\xE7\xE3o n\xE3o constant-time ou pular a checagem do v1.",
        references: [
          "https://docs.stripe.com/webhooks#verify-events",
          "https://cwe.mitre.org/data/definitions/347.html"
        ],
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    if (this.webhookSecret) {
      const oldTimestamp = Math.floor(Date.now() / 1e3) - 60 * 60 * 24;
      const validSigOldTs = buildSignature(payload, oldTimestamp, this.webhookSecret);
      const replay = await this.safePost(client, path, payload, {
        "Stripe-Signature": validSigOldTs
      });
      if (replay && replay.status >= 200 && replay.status < 300) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `stripe-webhook-replay:${path}`, location: path }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "high",
          title: `Webhook Stripe aceita replay com timestamp de 24h atr\xE1s: ${path}`,
          description: `${path} aceitou um evento assinado com timestamp de 24h atr\xE1s. Sem janela de toler\xE2ncia, qualquer evento interceptado/registrado pode ser replayed indefinidamente.`,
          endpoint: path,
          evidence: `POST ${path} com t=${oldTimestamp} (24h atr\xE1s) \u2192 HTTP ${replay.status}`,
          recommendation: "Configure toler\xE2ncia no constructEvent (padr\xE3o Stripe: 300s):\n```typescript\nstripe.webhooks.constructEvent(rawBody, sig, secret, 300);\n```",
          references: ["https://docs.stripe.com/webhooks#replay-attacks"],
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    }
  }
  async safePost(client, path, rawBody, headers) {
    try {
      const res = await client.request(path, {
        method: "POST",
        body: JSON.parse(rawBody),
        headers,
        timeoutMs: 5e3
      });
      return { status: res.status, raw: res.raw };
    } catch {
      return null;
    }
  }
};

// ../agents/dependencies/dist/index.js
import { join as join2 } from "path";
import { stat as stat2 } from "fs/promises";
var SEVERITY_MAP = {
  info: "info",
  low: "low",
  moderate: "medium",
  high: "high",
  critical: "critical"
};
var DependenciesAgent = class {
  constructor(runner = runCommand) {
    this.runner = runner;
  }
  runner;
  name = "DEPENDENCIES Agent";
  category = "deps";
  concurrency = 1;
  timeoutMs = 12e4;
  async run(scope) {
    const repoPath = scope.target.repoPath;
    if (!repoPath) {
      throw new SkippedCheck("sem repoPath \u2014 DependenciesAgent precisa do reposit\xF3rio local");
    }
    await this.ensurePackageJson(repoPath);
    let result;
    try {
      result = await this.runner("npm", ["audit", "--json"], { cwd: repoPath, timeoutMs: this.timeoutMs });
    } catch (err) {
      const e = err;
      if (e.code === "ENOENT") {
        throw new SkippedCheck("npm n\xE3o encontrado no PATH \u2014 n\xE3o foi poss\xEDvel auditar depend\xEAncias");
      }
      throw err;
    }
    const audit = this.parse(result.stdout);
    if (!audit) {
      const needsLock = /lockfile|package-lock|shrinkwrap|requires/i.test(result.stderr);
      throw new SkippedCheck(
        needsLock ? "sem package-lock.json/npm-shrinkwrap \u2014 npm audit n\xE3o p\xF4de rodar de forma confi\xE1vel" : `sa\xEDda de npm audit n\xE3o p\xF4de ser interpretada: ${result.stderr.slice(0, 200) || "vazia"}`
      );
    }
    return this.toFindings(scope, audit);
  }
  async ensurePackageJson(repoPath) {
    try {
      await stat2(join2(repoPath, "package.json"));
    } catch {
      throw new SkippedCheck(`sem package.json em ${repoPath} \u2014 n\xE3o parece um projeto Node`);
    }
  }
  parse(stdout) {
    try {
      const parsed = JSON.parse(stdout);
      if (parsed && typeof parsed === "object" && ("vulnerabilities" in parsed || "metadata" in parsed)) {
        return parsed;
      }
      return null;
    } catch {
      return null;
    }
  }
  toFindings(scope, audit) {
    const findings = [];
    const vulns = audit.vulnerabilities ?? {};
    for (const [name, vuln] of Object.entries(vulns)) {
      const severity = SEVERITY_MAP[vuln.severity] ?? "info";
      const via = this.summarizeVia(vuln.via);
      const proposedFix = this.buildFix(name, vuln.fixAvailable);
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `npm-audit:${name}`, location: name }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity,
        title: `Depend\xEAncia vulner\xE1vel: ${name} (${vuln.severity})`,
        description: `O pacote ${name}${vuln.range ? ` (faixa ${vuln.range})` : ""} tem vulnerabilidade ${vuln.severity} reportada por npm audit.${via ? ` Via: ${via}.` : ""}`,
        evidence: `npm audit \u2192 ${name}: severity=${vuln.severity}${vuln.range ? `, range=${vuln.range}` : ""}`,
        recommendation: proposedFix.description,
        proposedFix,
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    return findings;
  }
  summarizeVia(via) {
    if (!Array.isArray(via) || via.length === 0) return "";
    return via.map((v) => typeof v === "string" ? v : v.title ?? v.url ?? "").filter(Boolean).join("; ");
  }
  buildFix(name, fix) {
    if (fix === true) {
      return {
        description: `Rode \`npm audit fix\` para corrigir ${name} com updates compat\xEDveis.`,
        command: "npm audit fix",
        riskOfApplying: "npm audit fix aplica apenas updates semver-compat\xEDveis; rode a su\xEDte de testes depois. Risco baixo, mas n\xE3o nulo."
      };
    }
    if (fix && typeof fix === "object") {
      const major = fix.isSemVerMajor;
      return {
        description: `Atualize ${name} para ${fix.name}@${fix.version}${major ? " (MUDAN\xC7A DE MAJOR \u2014 pode quebrar)" : ""}.`,
        command: `npm install ${fix.name}@${fix.version}`,
        riskOfApplying: major ? "Atualiza\xE7\xE3o de major version: pode quebrar a API/comportamento. Leia o changelog e teste antes de aplicar." : "Atualiza\xE7\xE3o menor/patch: baixo risco; ainda assim rode os testes ap\xF3s aplicar."
      };
    }
    return {
      description: `Sem corre\xE7\xE3o autom\xE1tica para ${name}. Avalie substituir/remover a depend\xEAncia ou aguardar patch upstream.`,
      riskOfApplying: "Sem fix dispon\xEDvel: mitigar manualmente. Remover a depend\xEAncia pode quebrar funcionalidade \u2014 valide o uso antes."
    };
  }
};

// ../agents/secrets/dist/index.js
import { join as join3 } from "path";
import { tmpdir } from "os";
import { mkdtemp, readFile as readFile2, rm, readdir as readdir2 } from "fs/promises";
function looksLikeMissingBinary(code, stderr) {
  if (code === 127 || code === 9009) return true;
  return /reconhecido|recognized|command not found|no such file|cannot find|n[ãa]o encontrad/i.test(stderr);
}
function interpretGitleaks(input) {
  const { code, stderr, report } = input;
  if (looksLikeMissingBinary(code, stderr)) {
    return { kind: "skip", reason: "gitleaks n\xE3o encontrado no PATH \u2014 n\xE3o foi poss\xEDvel escanear segredos versionados" };
  }
  const trimmed = (report ?? "").trim();
  const parseReport = () => {
    if (!trimmed) return [];
    const parsed = JSON.parse(trimmed);
    return Array.isArray(parsed) ? parsed : [];
  };
  if (code === 0) return { kind: "findings", findings: parseReport() };
  if (code === 1) {
    if (!trimmed) {
      return { kind: "error", reason: 'gitleaks saiu com c\xF3digo 1 (vazamentos) mas n\xE3o gerou relat\xF3rio \u2014 resultado inconclusivo, n\xE3o tratado como "limpo"' };
    }
    return { kind: "findings", findings: parseReport() };
  }
  return { kind: "error", reason: `gitleaks saiu com c\xF3digo inesperado (${code ?? "null"})` };
}
var defaultGitleaksScan = async (repoPath, timeoutMs) => {
  const dir = await mkdtemp(join3(tmpdir(), "fracta-gitleaks-"));
  const reportPath = join3(dir, "report.json");
  try {
    let code;
    let stderr = "";
    try {
      const result = await runCommand(
        "gitleaks",
        [
          "detect",
          "--source",
          repoPath,
          "--no-banner",
          "--report-format",
          "json",
          "--report-path",
          reportPath
        ],
        { timeoutMs }
      );
      code = result.code;
      stderr = result.stderr;
    } catch (err) {
      const e = err;
      if (e.code === "ENOENT") {
        throw new SkippedCheck("gitleaks n\xE3o encontrado no PATH \u2014 n\xE3o foi poss\xEDvel escanear segredos versionados");
      }
      throw err;
    }
    let report = null;
    try {
      report = await readFile2(reportPath, "utf8");
    } catch {
      report = null;
    }
    const outcome = interpretGitleaks({ code, stderr, report });
    if (outcome.kind === "skip") throw new SkippedCheck(outcome.reason);
    if (outcome.kind === "error") throw new Error(outcome.reason);
    return outcome.findings;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};
var SecretsAgent = class {
  constructor(scan = defaultGitleaksScan) {
    this.scan = scan;
  }
  scan;
  name = "SECRETS Agent";
  category = "secrets";
  concurrency = 1;
  timeoutMs = 12e4;
  async run(scope) {
    const repoPath = scope.target.repoPath;
    if (!repoPath) {
      throw new SkippedCheck("sem repoPath \u2014 SecretsAgent precisa do reposit\xF3rio local");
    }
    const findings = [];
    let gitleaksSkip;
    try {
      const leaks = await this.scan(repoPath, this.timeoutMs);
      for (const leak of leaks) {
        findings.push(this.toLeakFinding(scope, leak));
      }
    } catch (err) {
      if (err instanceof SkippedCheck) {
        gitleaksSkip = err;
      } else {
        throw err;
      }
    }
    findings.push(...await this.hygieneFindings(scope, repoPath));
    if (gitleaksSkip) {
      if (findings.length === 0) throw new SkippedCheck(gitleaksSkip.motivo, true);
      findings.unshift(this.gitleaksSkipFinding(scope, gitleaksSkip.motivo));
    }
    return findings;
  }
  /** Finding informativo (nunca reprova) de que o scan de segredos versionados não rodou. */
  gitleaksSkipFinding(scope, motivo) {
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "gitleaks-not-run", location: "gitleaks" }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "info",
      title: "gitleaks ausente: segredos versionados N\xC3O foram escaneados",
      description: `N\xE3o foi poss\xEDvel escanear segredos versionados (${motivo}). As checagens de higiene abaixo rodaram normalmente, mas a AUS\xCANCIA de achado de segredo N\xC3O significa que o reposit\xF3rio est\xE1 livre de segredos \u2014 instale o gitleaks para a varredura completa.`,
      evidence: motivo,
      recommendation: "Instale o gitleaks (https://github.com/gitleaks/gitleaks) e rode o scan novamente para cobrir segredos versionados no hist\xF3rico Git.",
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  /** Mapeia um achado do gitleaks → Finding, SEM jamais incluir o valor do segredo. */
  toLeakFinding(scope, leak) {
    const ruleId = leak.RuleID ?? "unknown-rule";
    const file = leak.File ?? "unknown-file";
    const line = leak.StartLine ?? 0;
    const commit = leak.Commit ?? "";
    const shortCommit = commit ? commit.slice(0, 8) : "sem-commit";
    const proposedFix = {
      description: "Revogue/rotacione a credencial no provedor (Anthropic/Meta/Resend/etc.). Remover do hist\xF3rico Git N\xC3O substitui a rota\xE7\xE3o.",
      riskOfApplying: "Rotacionar pode derrubar integra\xE7\xF5es que usam a chave antiga at\xE9 atualizar o segredo no ambiente. Reescrever hist\xF3rico Git \xE9 destrutivo e exige force-push coordenado."
    };
    return {
      id: stableFindingId({
        saas: scope.target.name,
        camada: this.category,
        rule: `gitleaks:${ruleId}:${file}:${line}`,
        location: file
      }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "critical",
      title: `Segredo versionado: ${ruleId} em ${file}`,
      description: `gitleaks detectou um segredo versionado correspondente \xE0 regra ${ruleId} em ${file} (linha ${line}). O valor do segredo \xE9 deliberadamente omitido deste relat\xF3rio para n\xE3o recriar o vazamento.`,
      evidence: `${file}:${line} (commit ${shortCommit}) \u2014 regra ${ruleId}`,
      // Local estruturado → SARIF region.startLine (âncora inline no GitHub). Só com linha real (>0).
      location: line > 0 ? { file, line } : { file },
      recommendation: proposedFix.description,
      proposedFix,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  /** Checagens de higiene de configuração de segredos (read-only). */
  async hygieneFindings(scope, repoPath) {
    const findings = [];
    const gitignore = await this.readFileSafe(join3(repoPath, ".gitignore"));
    if (gitignore === null) {
      const committedEnv = await this.findEnvFiles(repoPath);
      if (committedEnv.length > 0) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "no-gitignore-with-env", location: ".env" }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "high",
          title: "Reposit\xF3rio sem .gitignore com arquivo .env versionado",
          description: `N\xE3o existe .gitignore neste reposit\xF3rio e foi encontrado pelo menos um arquivo de ambiente (${committedEnv.join(", ")}) que pode conter credenciais reais versionadas. Sem .gitignore, qualquer .env presente est\xE1 exposto ao hist\xF3rico Git.`,
          evidence: `Arquivos .env encontrados sem prote\xE7\xE3o de .gitignore: ${committedEnv.join(", ")}`,
          recommendation: "Crie um .gitignore ignorando `.env` e suas variantes. Execute `git rm --cached <arquivo>` para remover arquivos j\xE1 versionados e rotacione todos os segredos que possam ter sido expostos no hist\xF3rico.",
          proposedFix: {
            description: "Crie um .gitignore com a entrada `.env` (e variantes como `.env.*`). Use `git rm --cached .env` para remover do rastreamento e rotacione os segredos expostos no provedor.",
            riskOfApplying: "M\xE9dio. Criar o .gitignore \xE9 seguro, mas `git rm --cached` e reescrita de hist\xF3rico s\xE3o destrutivos e exigem coordena\xE7\xE3o com a equipe. Rotacionar segredos pode derrubar integra\xE7\xF5es at\xE9 atualizar os ambientes."
          },
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    } else if (!this.gitignoreCoversEnv(gitignore)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "env-not-gitignored", location: ".gitignore" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "high",
        title: "Arquivos .env n\xE3o ignorados pelo Git",
        description: "Existe um .gitignore mas ele n\xE3o ignora arquivos .env. Um .env com credenciais reais pode ser commitado por acidente.",
        evidence: ".gitignore n\xE3o cont\xE9m uma entrada que cubra `.env`",
        recommendation: "Adicione `.env` (e variantes como `.env.local`) ao .gitignore antes que credenciais sejam versionadas.",
        proposedFix: {
          description: "Adicione uma linha `.env` ao .gitignore.",
          riskOfApplying: "Baixo risco. Se um .env j\xE1 estiver versionado, adicion\xE1-lo ao .gitignore n\xE3o o remove do hist\xF3rico \u2014 \xE9 preciso `git rm --cached` e rotacionar os segredos expostos."
        },
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    const envExample = await this.readFileSafe(join3(repoPath, ".env.example"));
    if (envExample === null) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "no-env-example", location: ".env.example" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "low",
        title: "Sem .env.example",
        description: "N\xE3o existe um .env.example documentando as vari\xE1veis de ambiente necess\xE1rias. Sem ele, \xE9 comum compartilhar um .env real (com segredos).",
        evidence: "Arquivo .env.example ausente no reposit\xF3rio",
        recommendation: "Crie um .env.example listando as chaves esperadas com valores placeholder (ex.: `API_KEY=`), sem segredos reais.",
        proposedFix: {
          description: "Crie um .env.example com as chaves esperadas e valores vazios/placeholder.",
          riskOfApplying: "Risco nulo: arquivo de documenta\xE7\xE3o. Apenas garanta que n\xE3o contenha valores reais."
        },
        createdAt: /* @__PURE__ */ new Date()
      });
    } else if (this.envExampleHasRealValues(envExample)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "env-example-has-values", location: ".env.example" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "medium",
        title: ".env.example cont\xE9m valores reais",
        description: "O .env.example parece conter valores reais em vez de placeholders. Um .env.example deve documentar as chaves, n\xE3o expor segredos.",
        evidence: ".env.example tem linhas KEY=valor com valores n\xE3o-placeholder",
        recommendation: "Substitua os valores do .env.example por placeholders vazios (ex.: `API_KEY=`) e rotacione qualquer segredo que tenha vazado por ali.",
        proposedFix: {
          description: "Esvazie os valores no .env.example (mantenha s\xF3 as chaves) e rotacione segredos expostos.",
          riskOfApplying: "Baixo risco editar o arquivo; o risco real \xE9 o segredo j\xE1 exposto \u2014 rotacione-o no provedor."
        },
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    return findings;
  }
  /**
   * Lista arquivos .env (`.env`, `.env.*`) presentes diretamente na raiz do repositório.
   * Usado apenas quando `.gitignore` está ausente para detectar o pior cenário.
   */
  async findEnvFiles(repoPath) {
    try {
      const entries = await readdir2(repoPath);
      return entries.filter(
        (name) => name === ".env" || /^\.env\..+$/.test(name) && name !== ".env.example"
      );
    } catch {
      return [];
    }
  }
  async readFileSafe(path) {
    try {
      return await readFile2(path, "utf8");
    } catch {
      return null;
    }
  }
  /** True se o .gitignore tem alguma entrada que cobre `.env`. */
  gitignoreCoversEnv(content) {
    return content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).some((l) => {
      const normalized = l.replace(/^\//, "").replace(/\/$/, "");
      return normalized === ".env" || normalized === ".env*" || normalized === "*.env" || normalized.endsWith("/.env") || /^\.env\*?$/.test(normalized);
    });
  }
  /**
   * Heurística: o .env.example tem linhas `KEY=valor` com valor não-vazio e que
   * não parece placeholder. Tolerante a comentários e linhas em branco.
   */
  envExampleHasRealValues(content) {
    const lines = content.split(/\r?\n/);
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq <= 0) continue;
      let value = line.slice(eq + 1).trim();
      value = value.replace(/^["']|["']$/g, "").trim();
      if (!value) continue;
      if (this.looksLikeRealSecret(value)) return true;
    }
    return false;
  }
  /**
   * True só quando o valor PARECE um segredo real (não config nem placeholder). Conservador:
   * prefere deixar passar um segredo exótico a gritar em cima de config — o gitleaks é a
   * varredura primária; este check é um nudge de higiene do .env.example.
   */
  looksLikeRealSecret(value) {
    if (this.looksLikePlaceholder(value)) return false;
    if (/^(sk[-_][A-Za-z0-9]|rk_live_|whsec_[A-Za-z0-9]{8}|ghp_[A-Za-z0-9]{20}|gho_[A-Za-z0-9]{20}|xox[baprs]-|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20})/.test(value)) return true;
    if (/^(TROCAR|MUDAR|ALTERAR|CHANGE|DEFINA|COLOQUE|INSIRA|MESMO|SEU|SUA|YOUR|SET)[_-]/i.test(value)) return false;
    if (/^https?:\/\//i.test(value)) return false;
    if (/^[\w.+-]+@[\w.-]+\.\w+$/.test(value)) return false;
    if (/^\d+$/.test(value)) return false;
    if (/^\d+\s*[smhd]$/i.test(value)) return false;
    if (/^[A-Za-z][\w.-]*$/.test(value) && !(/[A-Za-z]/.test(value) && /\d/.test(value) && value.replace(/[^0-9]/g, "").length >= 4)) return false;
    if (value.length >= 24 && /[A-Za-z]/.test(value) && /\d/.test(value) && !/\s/.test(value) && !/\//.test(value)) return true;
    return false;
  }
  looksLikePlaceholder(value) {
    const v = value.toLowerCase();
    if (/^<.*>$/.test(value)) return true;
    if (/^\$\{.*\}$/.test(value)) return true;
    if (/^x+$/i.test(value)) return true;
    if (value.includes("...") || value.includes("\u2026")) return true;
    const placeholderWords = [
      "your",
      "change",
      "changeme",
      "placeholder",
      "example",
      "exemplo",
      "todo",
      "fixme",
      "replace",
      "sua-",
      "seu-",
      "dummy",
      "fake",
      "sample",
      "xxxx",
      "aqui",
      "here",
      "optional",
      "true",
      "false",
      "localhost"
    ];
    return placeholderWords.some((w) => v.includes(w));
  }
};

// ../agents/stack/dist/index.js
import { readdir as readdir3, readFile as readFile3, stat as stat3 } from "fs/promises";
import { join as join4, relative as relative2, basename } from "path";
var IGNORE_DIRS2 = /* @__PURE__ */ new Set(["node_modules", ".git", "dist", ".next", "coverage", ".turbo", "__tests__", "fracta-reports", ".worktrees", ".claude"]);
var TEXT_FILE = /\.(ts|tsx|js|jsx|mjs|cjs|json)$/i;
var ENV_FILE = /(^|[\\/])\.env($|\.[^\\/]+$)/i;
var NEXT_CONFIG = /(^|[\\/])next\.config\.(js|ts|mjs|cjs)$/i;
var StackAgent = class {
  name = "STACK Agent";
  category = "code";
  concurrency = 1;
  timeoutMs = 6e4;
  async run(scope) {
    const repoPath = scope.target.repoPath;
    if (!repoPath) {
      throw new SkippedCheck("sem repoPath \u2014 StackAgent precisa do reposit\xF3rio local para SAST");
    }
    const sources = await this.collectFiles(repoPath);
    const pkg = await this.readPackageJson(repoPath);
    const isNest = this.detectNest(sources, pkg);
    const out = [];
    this.checkHelmet(sources, isNest, out);
    this.checkRawSql(sources, out);
    this.checkValidationPipe(sources, isNest, out);
    this.checkRateLimiting(sources, isNest, pkg, out);
    this.checkTenantIsolation(sources, out);
    this.checkNextPublicSecrets(sources, out);
    this.checkCorsWildcard(sources, out);
    this.checkHardcodedKeys(sources, out);
    return out.map((f) => this.toFinding(scope, f));
  }
  // ---------------------------------------------------------------- helpers
  toFinding(scope, f) {
    return {
      id: stableFindingId({
        saas: scope.target.name,
        camada: this.category,
        rule: f.rule,
        location: f.location
      }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: f.severity,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      location: f.at,
      recommendation: f.recommendation,
      references: f.references,
      proposedFix: f.proposedFix,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  async readPackageJson(repoPath) {
    try {
      const raw = await readFile3(join4(repoPath, "package.json"), "utf-8");
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
  /** Deps + devDeps achatadas em um único conjunto de nomes. */
  allDeps(pkg) {
    const names = /* @__PURE__ */ new Set();
    if (!pkg) return names;
    for (const field of ["dependencies", "devDependencies", "peerDependencies"]) {
      const block = pkg[field];
      if (block && typeof block === "object") {
        for (const name of Object.keys(block)) names.add(name);
      }
    }
    return names;
  }
  detectNest(sources, pkg) {
    const hasMain = sources.some((s) => /(^|\/)main\.ts$/.test(s.relPath));
    if (hasMain) return true;
    for (const dep of this.allDeps(pkg)) {
      if (dep.startsWith("@nestjs/")) return true;
    }
    return false;
  }
  mainTsFiles(sources) {
    return sources.filter((s) => /(^|\/)main\.ts$/.test(s.relPath));
  }
  /** Nº da linha (1-based) onde `index` (offset em chars) cai no conteúdo. */
  lineAt(content, index) {
    let line = 1;
    for (let i = 0; i < index && i < content.length; i++) {
      if (content[i] === "\n") line++;
    }
    return line;
  }
  // ---------------------------------------------------------------- checks
  // 1) Helmet ausente (NestJS sem app.use(helmet()) em nenhum main.ts).
  checkHelmet(sources, isNest, out) {
    if (!isNest) return;
    const mains = this.mainTsFiles(sources);
    if (mains.length === 0) return;
    const hasHelmet = mains.some((s) => /helmet\s*\(/.test(s.content));
    if (hasHelmet) return;
    out.push({
      rule: "helmet-missing",
      severity: "medium",
      title: "Helmet ausente no bootstrap NestJS",
      description: "Aplica\xE7\xE3o NestJS detectada mas nenhuma chamada a `helmet(` foi encontrada no(s) main.ts. Sem Helmet, headers de seguran\xE7a (HSTS, X-Content-Type-Options, etc.) n\xE3o s\xE3o aplicados.",
      evidence: `${mains.map((m) => m.relPath).join(", ")} \u2014 nenhuma chamada helmet() encontrada`,
      recommendation: "Adicione `app.use(helmet())` no bootstrap, ap\xF3s criar a app.",
      proposedFix: {
        description: "Importe helmet e registre como middleware global: `import helmet from 'helmet'` e `app.use(helmet())` antes de `app.listen(...)`.",
        diff: "import helmet from 'helmet'\n// ...\napp.use(helmet())",
        command: "npm install helmet",
        riskOfApplying: "Os defaults de CSP do Helmet podem bloquear assets inline (scripts/estilos) e recursos de terceiros. Revise/ajuste a pol\xEDtica de CSP antes de subir em produ\xE7\xE3o para n\xE3o quebrar o frontend."
      }
    });
  }
  // 2) SQL raw com concatenação ($queryRawUnsafe/$executeRawUnsafe sempre; $queryRaw(/$executeRaw( com + ou template como arg normal).
  checkRawSql(sources, out) {
    const unsafe = /\$(?:query|execute)RawUnsafe\s*\(/g;
    const rawCall = /\$(?:query|execute)Raw\s*\(([^)]*)/g;
    for (const file of sources) {
      let m;
      while ((m = unsafe.exec(file.content)) !== null) {
        const line = this.lineAt(file.content, m.index);
        out.push(this.rawSqlFinding(file, line, m[0].replace(/\s*\($/, ""), "API unsafe ($queryRawUnsafe/$executeRawUnsafe)"));
      }
      while ((m = rawCall.exec(file.content)) !== null) {
        const args = m[1];
        const hasConcat = args.includes("+");
        const hasInterpolation = /`[^`]*\$\{[^}]*\}[^`]*`/.test(args);
        if (!hasConcat && !hasInterpolation) continue;
        const line = this.lineAt(file.content, m.index);
        out.push(
          this.rawSqlFinding(
            file,
            line,
            file.lines[line - 1]?.trim() ?? m[0],
            hasConcat ? "concatena\xE7\xE3o de string (+)" : "template literal interpolado passado como argumento"
          )
        );
      }
    }
  }
  rawSqlFinding(file, line, snippet, how) {
    return {
      rule: `raw-sql-concat:${file.relPath}:${line}`,
      location: file.relPath,
      at: { file: file.relPath, line },
      references: ["https://cwe.mitre.org/data/definitions/89.html", "A03:2021 - Injection"],
      severity: "high",
      title: `Risco de SQL injection (SQL raw): ${file.relPath}:${line}`,
      description: `SQL bruto constru\xEDdo via ${how}. Isso permite inje\xE7\xE3o de SQL. A forma SEGURA \xE9 o tagged template \`prisma.$queryRaw\`...\`\` (sem par\xEAntese), que parametriza as interpola\xE7\xF5es automaticamente.`,
      evidence: `${file.relPath}:${line} \u2014 ${snippet.slice(0, 200)}`,
      recommendation: "Use o tagged template `prisma.$queryRaw`SELECT ... WHERE id = ${id}`` (parametrizado) ou `Prisma.sql`/`$queryRawUnsafe` apenas com `Prisma.sql` e placeholders. Nunca concatene input do usu\xE1rio.",
      proposedFix: {
        description: 'Converta para tagged template parametrizado: troque `prisma.$queryRawUnsafe("... " + id)` por `prisma.$queryRaw`SELECT ... WHERE id = ${id}``.',
        riskOfApplying: "A reescrita muda a forma da chamada; valide que a query continua v\xE1lida e que os tipos das interpola\xE7\xF5es s\xE3o suportados pelo driver. Teste a query ap\xF3s a convers\xE3o."
      }
    };
  }
  // 3) ValidationPipe ausente (NestJS) ou sem whitelist:true.
  checkValidationPipe(sources, isNest, out) {
    const usages = sources.filter((s) => /ValidationPipe/.test(s.content));
    if (usages.length === 0) {
      if (!isNest) return;
      out.push({
        rule: "validationpipe-missing",
        severity: "medium",
        title: "NestJS sem ValidationPipe global",
        description: "Aplica\xE7\xE3o NestJS detectada mas nenhum uso de `ValidationPipe` foi encontrado. Sem ela, DTOs n\xE3o s\xE3o validados e propriedades n\xE3o declaradas passam direto para os handlers.",
        recommendation: "Registre `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))` no bootstrap.",
        proposedFix: {
          description: "No main.ts: `app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))`.",
          diff: "app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }))",
          riskOfApplying: "Com `whitelist`/`forbidNonWhitelisted`, requests que enviam campos extras passam a falhar (400). Pode quebrar clientes que mandam payloads maiores que o DTO. Audite os contratos antes."
        }
      });
      return;
    }
    const hasWhitelist = usages.some((s) => {
      const idx = s.content.indexOf("ValidationPipe");
      const window = s.content.slice(idx, idx + 400);
      return /whitelist\s*:\s*true/.test(window) || /whitelist\s*:\s*true/.test(s.content);
    });
    if (hasWhitelist) return;
    const first = usages[0];
    const line = this.lineAt(first.content, first.content.indexOf("ValidationPipe"));
    out.push({
      rule: "validationpipe-no-whitelist",
      location: first.relPath,
      at: { file: first.relPath, line },
      severity: "medium",
      title: "ValidationPipe sem whitelist: true",
      description: "O `ValidationPipe` \xE9 usado mas sem `whitelist: true`. Sem whitelist, propriedades n\xE3o declaradas no DTO n\xE3o s\xE3o removidas, abrindo espa\xE7o para mass-assignment.",
      evidence: `${first.relPath}:${line} \u2014 ValidationPipe sem whitelist: true`,
      recommendation: "Configure `new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`.",
      proposedFix: {
        description: "Adicione `whitelist: true` (e idealmente `forbidNonWhitelisted: true`) \xE0s op\xE7\xF5es do ValidationPipe.",
        diff: "new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })",
        riskOfApplying: "Requests com campos extras passar\xE3o a ser rejeitados/limpos. Pode afetar clientes existentes \u2014 valide os payloads aceitos."
      }
    });
  }
  // 4) Rate limiting (NestJS sem @nestjs/throttler nas deps e sem ThrottlerModule no código).
  checkRateLimiting(sources, isNest, pkg, out) {
    if (!isNest) return;
    const deps = this.allDeps(pkg);
    const hasDep = deps.has("@nestjs/throttler");
    const usesModule = sources.some((s) => /ThrottlerModule/.test(s.content));
    if (hasDep || usesModule) return;
    out.push({
      rule: "throttler-missing",
      severity: "medium",
      title: "Sem rate limiting (@nestjs/throttler ausente)",
      description: "Aplica\xE7\xE3o NestJS sem `@nestjs/throttler` nas depend\xEAncias e sem uso de `ThrottlerModule`. Rotas de login ficam expostas a brute force e rotas de LLM/IA a abuso com impacto FINANCEIRO direto (cada chamada custa tokens) e DoS de custo.",
      recommendation: "Adicione `@nestjs/throttler`, registre o `ThrottlerModule.forRoot(...)` e aplique limites mais estritos em rotas de login e em endpoints que disparam chamadas a LLM/provedores pagos.",
      proposedFix: {
        description: "Instale e configure: `ThrottlerModule.forRoot([{ ttl: 60000, limit: 10 }])` no AppModule e `@Throttle({ default: { limit: 5, ttl: 60000 } })` em rotas sens\xEDveis (login, IA).",
        command: "npm install @nestjs/throttler",
        riskOfApplying: "Limites mal calibrados podem bloquear tr\xE1fego leg\xEDtimo (falsos 429). Calibre por rota e considere identidade/tenant na chave do throttler, n\xE3o s\xF3 IP."
      }
    });
  }
  // 5) Isolamento de tenant — HEURÍSTICA conservadora p/ revisão humana (severity low).
  checkTenantIsolation(sources, out) {
    const finders = /\.(findMany|findFirst|findUnique)\s*\(/g;
    const tenantKey = /tenantid|ownerid|accountid|orgid/i;
    for (const file of sources) {
      let m;
      while ((m = finders.exec(file.content)) !== null) {
        const line = this.lineAt(file.content, m.index);
        const start = Math.max(0, m.index - 300);
        const window = file.content.slice(start, m.index + 400);
        const hasWhere = /where/i.test(window);
        const hasTenant = tenantKey.test(window);
        if (hasTenant) continue;
        out.push({
          rule: `tenant-isolation-review:${file.relPath}:${line}`,
          location: file.relPath,
          at: { file: file.relPath, line },
          references: ["https://cwe.mitre.org/data/definitions/639.html", "A01:2021 - Broken Access Control"],
          severity: "low",
          title: `Poss\xEDvel falta de isolamento de tenant (heur\xEDstica): ${file.relPath}:${line}`,
          description: `HEUR\xCDSTICA (requer revis\xE3o humana): consulta Prisma \`${m[1]}\` ${hasWhere ? "com `where` mas" : "sem `where` e"} sem refer\xEAncia a \`tenantId|ownerId|accountId|orgId\` na vizinhan\xE7a. Pode haver vazamento entre tenants \u2014 ou pode ser uma query leg\xEDtimamente global. Confirme manualmente.`,
          evidence: `${file.relPath}:${line} \u2014 ${file.lines[line - 1]?.trim().slice(0, 160) ?? m[0]}`,
          recommendation: "Confirme que a query \xE9 escopada ao tenant/owner (filtro no `where` ou Prisma extension/RLS). Se for intencionalmente global, suprima este finding.",
          proposedFix: {
            description: "Adicione o escopo de tenant no `where` (ex.: `where: { tenantId: ctx.tenantId, ... }`) ou aplique uma Prisma client extension/Postgres RLS que force o filtro em todas as queries.",
            riskOfApplying: "\xC9 uma heur\xEDstica: pode ser falso-positivo (query global leg\xEDtima). Aplicar um filtro de tenant numa query que deveria ser global esconderia dados. Revise antes de mudar."
          }
        });
      }
    }
  }
  // 6a) Segredos NEXT_PUBLIC_ em .env*/next.config.* cujo NOME parece segredo.
  checkNextPublicSecrets(sources, out) {
    const secretName = /KEY|SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL/i;
    const publicByDesignName = /PUBLISHABLE|PUBLIC_?KEY/i;
    const publishableValue = /=\s*["']?pk_(?:live|test)_/i;
    const re = /\bNEXT_PUBLIC_([A-Z0-9_]+)\b/g;
    for (const file of sources) {
      if (!file.isEnvLike) continue;
      const seen = /* @__PURE__ */ new Set();
      let m;
      while ((m = re.exec(file.content)) !== null) {
        const suffix = m[1];
        const varName = `NEXT_PUBLIC_${suffix}`;
        if (seen.has(varName)) continue;
        if (!secretName.test(varName)) continue;
        if (publicByDesignName.test(varName) || publishableValue.test(file.content.slice(m.index, m.index + 160))) continue;
        seen.add(varName);
        const line = this.lineAt(file.content, m.index);
        out.push({
          rule: `next-public-secret:${varName}`,
          location: file.relPath,
          at: { file: file.relPath, line },
          references: ["https://cwe.mitre.org/data/definitions/200.html", "A01:2021 - Broken Access Control"],
          severity: "high",
          title: `Segredo exposto via NEXT_PUBLIC_: ${varName}`,
          description: `A vari\xE1vel \`${varName}\` (em ${file.relPath}) usa o prefixo \`NEXT_PUBLIC_\`. No Next.js, tudo com esse prefixo \xE9 EMBUTIDO no bundle do cliente e fica P\xDABLICO \u2014 vis\xEDvel a qualquer visitante. O nome sugere que isto \xE9 um segredo, ent\xE3o ele est\xE1 efetivamente vazado.`,
          evidence: `${file.relPath}:${line} \u2014 ${varName} (valor omitido)`,
          recommendation: "Remova o prefixo `NEXT_PUBLIC_` deste segredo e consuma-o apenas no servidor (route handlers, server actions, API). Rotacione a credencial, pois ela pode j\xE1 ter sido buildada para o cliente.",
          proposedFix: {
            description: `Renomeie \`${varName}\` para \`${suffix}\` (sem o prefixo) e mova o uso para o lado servidor. Rotacione a chave comprometida.`,
            riskOfApplying: "Remover o prefixo torna a vari\xE1vel indispon\xEDvel no c\xF3digo do cliente \u2014 qualquer uso client-side quebrar\xE1 e precisa ser movido para o servidor. Rotacionar a chave invalida a antiga em uso."
          }
        });
      }
    }
  }
  // 6b) CORS wildcard: origin: '*' / origin: true, ou Access-Control-Allow-Origin: '*'.
  checkCorsWildcard(sources, out) {
    const patterns = [
      /origin\s*:\s*['"`]\*['"`]/g,
      /origin\s*:\s*true\b/g,
      /['"`]Access-Control-Allow-Origin['"`]\s*[,:]\s*['"`]\*['"`]/g
    ];
    for (const file of sources) {
      if (file.isEnvLike) continue;
      for (const re of patterns) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(file.content)) !== null) {
          const line = this.lineAt(file.content, m.index);
          out.push({
            rule: `cors-wildcard:${file.relPath}:${line}`,
            location: file.relPath,
            at: { file: file.relPath, line },
            references: ["https://cwe.mitre.org/data/definitions/942.html", "A05:2021 - Security Misconfiguration"],
            severity: "high",
            title: `CORS permissivo (wildcard): ${file.relPath}:${line}`,
            description: "Configura\xE7\xE3o de CORS com origem curinga (`*` ou `true`). Isso permite que qualquer site fa\xE7a requisi\xE7\xF5es autenticadas ao backend; combinado com credenciais, exp\xF5e a API a CSRF/exfiltra\xE7\xE3o cross-origin.",
            evidence: `${file.relPath}:${line} \u2014 ${file.lines[line - 1]?.trim().slice(0, 160) ?? m[0]}`,
            recommendation: "Restrinja a origem a uma allowlist expl\xEDcita dos dom\xEDnios do frontend. Nunca combine origem `*` com `credentials: true`.",
            proposedFix: {
              description: "Troque por allowlist: `app.enableCors({ origin: ['https://app.seu-dominio.com'], credentials: true })`.",
              diff: "origin: ['https://app.seu-dominio.com']",
              riskOfApplying: "Restringir a origem pode bloquear front-ends/ambientes leg\xEDtimos n\xE3o listados (ex.: preview/staging). Liste todos os dom\xEDnios v\xE1lidos antes de aplicar."
            }
          });
        }
      }
    }
  }
  // 6c) Chaves de provider hardcoded em source (não .env). Evidência MASCARADA.
  checkHardcodedKeys(sources, out) {
    const patterns = [
      { re: /sk_live_[A-Za-z0-9]{6,}/g, label: "Stripe live secret key" },
      { re: /sk_test_[A-Za-z0-9]{6,}/g, label: "Stripe test secret key" },
      { re: /AIza[0-9A-Za-z_\-]{20,}/g, label: "Google API key" }
    ];
    for (const file of sources) {
      if (file.isEnvLike) continue;
      if (!/(^|\/)src\//.test(file.relPath)) continue;
      for (const { re, label } of patterns) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(file.content)) !== null) {
          const key = m[0];
          const line = this.lineAt(file.content, m.index);
          out.push({
            rule: `hardcoded-key:${file.relPath}:${line}`,
            location: file.relPath,
            at: { file: file.relPath, line },
            references: ["https://cwe.mitre.org/data/definitions/798.html", "A07:2021 - Identification and Authentication Failures"],
            severity: "high",
            title: `Chave de provider hardcoded (${label}): ${file.relPath}:${line}`,
            description: `Uma ${label} aparece embutida no c\xF3digo-fonte (${file.relPath}). Segredos em source s\xE3o commitados, distribu\xEDdos e frequentemente buildados para o cliente \u2014 trate como comprometidos.`,
            evidence: `${file.relPath}:${line} \u2014 ${this.maskKey(key)}`,
            recommendation: "Mova a chave para vari\xE1vel de ambiente (server-side) e rotacione-a imediatamente, pois j\xE1 est\xE1 no hist\xF3rico do git.",
            proposedFix: {
              description: "Substitua o literal por `process.env.NOME_DA_CHAVE` e rotacione a credencial no provedor.",
              riskOfApplying: "Remover o literal exige que a vari\xE1vel de ambiente esteja configurada em todos os ambientes, sen\xE3o a integra\xE7\xE3o quebra em runtime. Rotacionar invalida a chave antiga em uso."
            }
          });
        }
      }
    }
  }
  /** Mascara a chave: mostra só os primeiros 7 chars + '…'. Nunca ecoa o segredo inteiro. */
  maskKey(key) {
    return `${key.slice(0, 7)}\u2026`;
  }
  // ---------------------------------------------------------------- walk
  async collectFiles(repoPath) {
    const files = [];
    await this.walkDir(repoPath, repoPath, files);
    return files;
  }
  async walkDir(dir, baseDir, files) {
    let entries;
    try {
      entries = await readdir3(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORE_DIRS2.has(entry)) continue;
      const fullPath = join4(dir, entry);
      try {
        const info = await stat3(fullPath);
        if (info.isDirectory()) {
          await this.walkDir(fullPath, baseDir, files);
          continue;
        }
        if (!this.isReadableFile(fullPath, entry)) continue;
        const content = await readFile3(fullPath, "utf-8");
        const relPath = relative2(baseDir, fullPath).replace(/\\/g, "/");
        const name = basename(entry);
        files.push({
          relPath,
          content,
          lines: content.split(/\r?\n/),
          isEnvLike: ENV_FILE.test(name) || NEXT_CONFIG.test(name)
        });
      } catch {
      }
    }
  }
  isReadableFile(fullPath, entry) {
    const name = basename(entry);
    if (ENV_FILE.test(name)) return true;
    if (NEXT_CONFIG.test(name)) return true;
    return TEXT_FILE.test(name);
  }
};

// ../agents/infra/dist/index.js
import { readFile as readFile4 } from "fs/promises";
import { connect } from "net";
var defaultProbePort = (host, port, timeoutMs) => new Promise((resolve) => {
  const socket = connect({ host, port });
  let settled = false;
  const finish = (open) => {
    if (settled) return;
    settled = true;
    socket.destroy();
    resolve(open);
  };
  socket.setTimeout(timeoutMs);
  socket.once("connect", () => finish(true));
  socket.once("timeout", () => finish(false));
  socket.once("error", () => finish(false));
});
var DB_PORTS = [
  { port: 5432, nome: "PostgreSQL" },
  { port: 6379, nome: "Redis" }
];
var PROBE_TIMEOUT_MS = 4e3;
var InfraAgent = class {
  constructor(probePort = defaultProbePort) {
    this.probePort = probePort;
  }
  probePort;
  name = "INFRA Agent";
  category = "infra";
  concurrency = 1;
  timeoutMs = 3e4;
  async run(scope) {
    const infra = scope.target.infra;
    if (!infra || !infra.host && !infra.sshConfigPath && !infra.dockerComposePath) {
      throw new SkippedCheck(
        "sem dados de infra (host/sshConfigPath/dockerComposePath) \u2014 InfraAgent n\xE3o tem o que observar"
      );
    }
    const findings = [];
    if (infra.host) {
      findings.push(...await this.checkExposedDbPorts(scope, infra.host));
    }
    if (infra.sshConfigPath) {
      findings.push(...await this.checkSshConfig(scope, infra.sshConfigPath));
    }
    if (infra.dockerComposePath) {
      findings.push(...await this.checkDockerCompose(scope, infra.dockerComposePath));
    }
    return findings;
  }
  // 1) Portas de banco expostas — o achado de infra mais perigoso. -----------
  async checkExposedDbPorts(scope, host) {
    const findings = [];
    for (const { port, nome } of DB_PORTS) {
      const open = await this.probePort(host, port, PROBE_TIMEOUT_MS);
      if (!open) continue;
      const location = `${host}:${port}`;
      findings.push(this.finding(scope, {
        rule: `db-port-exposed:${port}`,
        location,
        severity: "critical",
        title: `Porta de banco exposta \xE0 internet: ${nome} (${port})`,
        description: `A porta ${port} (${nome}) ACEITOU conex\xE3o TCP a partir do exterior em ${location}. Um banco de dados/cache alcan\xE7\xE1vel pela internet \xE9 o vetor de comprometimento mais grave: permite ataques de for\xE7a bruta, explora\xE7\xE3o direta e exfiltra\xE7\xE3o de dados.`,
        evidence: `TCP connect aceito em ${location} (porta aberta externamente)`,
        recommendation: `Bloqueie a porta ${port} no firewall e fa\xE7a o servi\xE7o escutar apenas em localhost (127.0.0.1).`,
        proposedFix: {
          description: `Bloqueie a porta no firewall e vincule o ${nome} ao localhost. Ex.: \`sudo ufw deny ${port}/tcp\` e configure o ${nome} para bind 127.0.0.1.`,
          command: `sudo ufw deny ${port}/tcp`,
          riskOfApplying: `PROPOSTA \u2014 revise antes. Bloquear uma porta EM USO pode cortar a conectividade da aplica\xE7\xE3o se ela se conecta ao ${nome} por esta interface p\xFAblica. Garanta que a app usa rede interna/localhost antes de bloquear, ou voc\xEA derruba o servi\xE7o.`
        }
      }));
    }
    return findings;
  }
  // 2) sshd_config — leitura do arquivo (se fornecido e legível). ------------
  async checkSshConfig(scope, path) {
    const text = await this.readTextOrSkipSubcheck(path);
    if (text === null) return [];
    const findings = [];
    if (!this.sshDirectiveSet(text, "PasswordAuthentication", "no")) {
      findings.push(this.finding(scope, {
        rule: "ssh-password-auth",
        location: path,
        severity: "high",
        title: "SSH permite autentica\xE7\xE3o por senha",
        description: `O sshd_config (${path}) n\xE3o define \`PasswordAuthentication no\`. Login por senha exp\xF5e o servidor a for\xE7a bruta e credential stuffing; chaves SSH s\xE3o o padr\xE3o recomendado.`,
        evidence: `sshd_config sem \`PasswordAuthentication no\``,
        recommendation: "Desative a autentica\xE7\xE3o por senha e use apenas chaves SSH.",
        proposedFix: {
          description: "Em sshd_config defina:\n  PasswordAuthentication no\n  ChallengeResponseAuthentication no\nDepois: `sudo systemctl reload sshd`.",
          command: "sudo systemctl reload sshd",
          riskOfApplying: "PROPOSTA \u2014 revise antes. Desativar senha SEM ter uma chave SSH funcionando TRANCA voc\xEA para fora do servidor. Confirme login por chave numa sess\xE3o paralela antes de aplicar e recarregar o sshd."
        }
      }));
    }
    if (!this.sshDirectiveSet(text, "PermitRootLogin", "no")) {
      findings.push(this.finding(scope, {
        rule: "ssh-root-login",
        location: path,
        severity: "high",
        title: "SSH permite login direto como root",
        description: `O sshd_config (${path}) n\xE3o define \`PermitRootLogin no\`. Login direto de root remove a barreira de auditoria/sudo e torna o alvo de for\xE7a bruta o usu\xE1rio mais privilegiado.`,
        evidence: `sshd_config sem \`PermitRootLogin no\``,
        recommendation: "Pro\xEDba login direto de root; acesse via usu\xE1rio comum + sudo.",
        proposedFix: {
          description: "Em sshd_config defina:\n  PermitRootLogin no\nDepois: `sudo systemctl reload sshd`.",
          command: "sudo systemctl reload sshd",
          riskOfApplying: "PROPOSTA \u2014 revise antes. Se o \xFAnico acesso for via root, proibir root login te tranca para fora. Garanta um usu\xE1rio n\xE3o-root com sudo e chave SSH funcionando antes de aplicar."
        }
      }));
    }
    return findings;
  }
  // 3) docker-compose — heurística por linha, SEM dependência de yaml. -------
  async checkDockerCompose(scope, path) {
    const text = await this.readTextOrSkipSubcheck(path);
    if (text === null) return [];
    const findings = [];
    const lines = text.split(/\r?\n/);
    const seenPublished = /* @__PURE__ */ new Set();
    for (const { port, nome } of DB_PORTS) {
      const idx = lines.findIndex((l) => this.publishesDbPort(l, port));
      if (idx === -1 || seenPublished.has(port)) continue;
      seenPublished.add(port);
      findings.push(this.finding(scope, {
        rule: `compose-db-published:${port}`,
        location: `${path}:${idx + 1}`,
        severity: "high",
        title: `docker-compose publica porta de banco no host: ${nome} (${port})`,
        description: `O compose mapeia a porta ${port} (${nome}) para o host via \`ports:\` (linha ${idx + 1}), o que pode expor o banco para fora do Docker. Use \`expose:\` / rede interna para que apenas outros containers alcancem o servi\xE7o.`,
        evidence: `linha ${idx + 1}: ${this.sanitizeLine(lines[idx])}`,
        recommendation: `Troque \`ports:\` por \`expose: ["${port}"]\` (ou rede interna) para o servi\xE7o ${nome}, assim ele n\xE3o fica acess\xEDvel pelo host.`,
        proposedFix: {
          description: `No servi\xE7o do ${nome}, remova o mapeamento \`ports: "${port}:${port}"\` e use \`expose: ["${port}"]\`, deixando o acesso restrito \xE0 rede interna do Compose.`,
          riskOfApplying: `PROPOSTA \u2014 revise antes. Se algum processo no HOST (fora do Docker) depende dessa porta publicada, remov\xEA-la quebra essa conex\xE3o. Confirme que s\xF3 containers usam o ${nome} antes de aplicar.`
        }
      }));
    }
    lines.forEach((line, i) => {
      const varName = this.plaintextSecretVarName(line);
      if (!varName) return;
      findings.push(this.finding(scope, {
        rule: "compose-plaintext-secret",
        location: `${path}:${i + 1}`,
        severity: "high",
        title: `Segredo em texto plano no docker-compose: ${varName}`,
        description: `A vari\xE1vel \`${varName}\` (linha ${i + 1}) tem um valor literal embutido no compose, n\xE3o uma interpola\xE7\xE3o \`\${...}\`. Segredos versionados vazam pelo git/imagem. (O valor N\xC3O \xE9 exibido aqui.)`,
        // NUNCA ecoa o valor: só o nome da var + linha.
        evidence: `linha ${i + 1}: vari\xE1vel \`${varName}\` com valor literal (valor omitido por seguran\xE7a)`,
        recommendation: `Mova o segredo para vari\xE1vel de ambiente externa (\`${varName}: \${${varName}}\`) ou docker secrets, e rotacione o valor j\xE1 exposto.`,
        proposedFix: {
          description: `Substitua o valor literal por interpola\xE7\xE3o: \`${varName}: \${${varName}}\` e forne\xE7a o valor via \`.env\`/secret fora do versionamento. Rotacione o segredo, pois ele j\xE1 esteve em texto plano.`,
          riskOfApplying: "PROPOSTA \u2014 revise antes. Trocar o valor por interpola\xE7\xE3o exige que a vari\xE1vel esteja definida no ambiente/.env; se n\xE3o estiver, o container sobe sem o segredo. Defina-a antes de aplicar."
        }
      }));
    });
    if (this.hasServices(lines) && !lines.some((l) => /^\s*user\s*:/i.test(l))) {
      findings.push(this.finding(scope, {
        rule: "compose-no-user",
        location: path,
        severity: "low",
        title: "Containers possivelmente rodando como root",
        description: `O compose (${path}) define servi\xE7os mas nenhuma diretiva \`user:\`. Sem ela, os containers tendem a rodar como root, ampliando o impacto de um escape de container.`,
        evidence: "nenhuma diretiva `user:` encontrada no compose com servi\xE7os",
        recommendation: "Defina `user:` (UID n\xE3o-root) em cada servi\xE7o ou no Dockerfile.",
        proposedFix: {
          description: 'Adicione `user: "1000:1000"` (ou UID n\xE3o-root apropriado) aos servi\xE7os, ou use `USER` no Dockerfile.',
          riskOfApplying: "PROPOSTA \u2014 revise antes. Rodar como n\xE3o-root pode quebrar servi\xE7os que precisam de portas <1024 ou de permiss\xF5es de arquivo/volume espec\xEDficas. Teste cada servi\xE7o antes de aplicar amplamente."
        }
      }));
    }
    return findings;
  }
  // --- helpers ---------------------------------------------------------------
  /** Lê arquivo como texto; `null` quando ausente/ilegível (sub-check é pulado, não falha). */
  async readTextOrSkipSubcheck(path) {
    try {
      return await readFile4(path, "utf8");
    } catch {
      return null;
    }
  }
  /** `true` se a diretiva ssh está setada exatamente com o valor esperado (ignora comentários). */
  sshDirectiveSet(text, directive, value) {
    const re = new RegExp(`^\\s*${directive}\\s+${value}\\s*$`, "im");
    return re.test(text);
  }
  /** Linha de `ports:` que publica a porta de DB para o host (ex.: "5432:5432", "127.0.0.1:5432:5432:..."). */
  publishesDbPort(line, port) {
    return new RegExp(`(^|[\\s"':])${port}\\s*:\\s*\\d`).test(line);
  }
  /** Nome da var de um segredo literal (não interpolação). `null` se não houver. */
  plaintextSecretVarName(line) {
    const m = line.match(/(\w*(?:PASSWORD|SECRET|TOKEN|API_KEY)\w*)\s*[:=]\s*(\S+)/i);
    if (!m) return null;
    const value = m[2];
    if (/^["']?\$\{?\w+\}?["']?$/.test(value)) return null;
    return m[1];
  }
  /** Há um bloco `services:` com pelo menos um serviço definido. */
  hasServices(lines) {
    const svcIdx = lines.findIndex((l) => /^\s*services\s*:/i.test(l));
    if (svcIdx === -1) return false;
    for (let i = svcIdx + 1; i < lines.length; i++) {
      const l = lines[i];
      if (/^\S/.test(l) && !/^\s*$/.test(l)) break;
      if (/^\s+[\w.-]+\s*:\s*$/.test(l)) return true;
    }
    return false;
  }
  /** Remove o valor após `:`/`=` de uma linha, preservando a chave (p/ evidência segura). */
  sanitizeLine(line) {
    return line.trim();
  }
  /** Monta um Finding com os campos invariantes do agente. */
  finding(scope, f) {
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: f.rule, location: f.location }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: f.severity,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      recommendation: f.recommendation,
      proposedFix: f.proposedFix,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
};

// ../agents/semgrep/dist/index.js
function looksLikeMissingBinary2(stderr) {
  return /reconhecido|recognized|command not found|no such file|cannot find|n[ãa]o encontrad|not found/i.test(stderr);
}
function interpretSemgrep(input) {
  const { code, stdout, stderr } = input;
  if (looksLikeMissingBinary2(stderr) && !stdout.trim()) {
    return { kind: "skip", reason: "semgrep n\xE3o encontrado no PATH \u2014 SAST sem\xE2ntico n\xE3o executado (instale: `pipx install semgrep`)" };
  }
  const trimmed = stdout.trim();
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed.results)) return { kind: "findings", results: parsed.results };
    } catch {
    }
  }
  if (code === 0) return { kind: "findings", results: [] };
  return { kind: "error", reason: `semgrep terminou com code ${code} e sa\xEDda n\xE3o-parse\xE1vel: ${(stderr || stdout).slice(0, 200)}` };
}
var SEV = { ERROR: "high", WARNING: "medium", INFO: "low" };
var CONF = { HIGH: "high", MEDIUM: "medium", LOW: "low" };
function mapSemgrepFindings(input) {
  const { saas, runId, results } = input;
  return results.map((r) => {
    const severity = SEV[String(r.extra.severity).toUpperCase()] ?? "medium";
    const confidence = CONF[String(r.extra.metadata?.confidence ?? "").toUpperCase()] ?? "medium";
    const cwe = r.extra.metadata?.cwe ?? [];
    const owasp = r.extra.metadata?.owasp ?? [];
    const refs = [...cwe, ...owasp, ...r.extra.metadata?.references ?? []];
    const shortRule = r.check_id.split(".").slice(-2).join(".") || r.check_id;
    return {
      id: stableFindingId({ saas, camada: "code", rule: `semgrep:${r.check_id}`, location: `${r.path}:${r.start.line}` }),
      runId,
      agent: "SEMGREP Agent",
      category: "code",
      camada: "code",
      severity,
      confidence,
      title: `SAST (semgrep): ${shortRule} \u2014 ${r.path}:${r.start.line}`,
      description: `${r.extra.message ?? r.check_id} (regra: ${r.check_id}). An\xE1lise sem\xE2ntica/dataflow \u2014 n\xE3o \xE9 s\xF3 regex.`,
      location: { file: r.path, line: r.start.line },
      evidence: r.extra.lines ? `${r.path}:${r.start.line} \u2014 ${r.extra.lines.trim().slice(0, 200)}` : `${r.path}:${r.start.line}`,
      recommendation: r.extra.message ?? "Reveja o trecho sinalizado pelo semgrep e aplique a corre\xE7\xE3o da regra.",
      references: refs.length ? refs : ["https://semgrep.dev/"],
      createdAt: /* @__PURE__ */ new Date()
    };
  });
}
var DEFAULT_CONFIG = process.env.FRACTA_SEMGREP_CONFIG ?? "p/security-audit";
function semgrepSkipReasonFor(err) {
  const e = err;
  if (e?.code === "ENOENT") {
    return "semgrep n\xE3o encontrado no PATH \u2014 SAST sem\xE2ntico n\xE3o executado (instale: `pipx install semgrep`)";
  }
  if (/timeout/i.test(e?.message ?? "")) {
    return "semgrep excedeu o tempo \u2014 SAST sem\xE2ntico n\xE3o conclu\xEDdo (\xE9 lento no Windows; rode em CI/Linux ou ajuste FRACTA_SEMGREP_TIMEOUT)";
  }
  return null;
}
var defaultSemgrepScan = async (repoPath, timeoutMs) => {
  let code;
  let stdout = "";
  let stderr = "";
  try {
    const result = await runCommand(
      "semgrep",
      [
        "scan",
        "--config",
        DEFAULT_CONFIG,
        "--json",
        "--quiet",
        // Respeita .gitignore (pula node_modules/dist) — SEM isto varreria tudo.
        // Auto-bounds do próprio semgrep para não pendurar: timeout por-regra/arquivo,
        // desiste do arquivo após 3 regras estourarem, sem telemetria de rede.
        "--timeout",
        "15",
        "--timeout-threshold",
        "3",
        "--metrics=off",
        repoPath
      ],
      { timeoutMs }
    );
    code = result.code;
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (err) {
    const reason = semgrepSkipReasonFor(err);
    if (reason) throw new SkippedCheck(reason);
    throw err;
  }
  const outcome = interpretSemgrep({ code, stdout, stderr });
  if (outcome.kind === "skip") throw new SkippedCheck(outcome.reason);
  if (outcome.kind === "error") throw new Error(outcome.reason);
  return outcome.results;
};
var SemgrepAgent = class {
  constructor(scan = defaultSemgrepScan) {
    this.scan = scan;
  }
  scan;
  name = "SEMGREP Agent";
  category = "code";
  concurrency = 1;
  // Timeout total (s) configurável — default 120s. Backstop do runCommand: se o
  // semgrep pendurar (Windows), o scan degrada para `skipped`, não trava.
  timeoutMs = Math.max(10, Number(process.env.FRACTA_SEMGREP_TIMEOUT ?? 120)) * 1e3;
  async run(scope) {
    const repoPath = scope.target.repoPath;
    if (!repoPath) {
      throw new SkippedCheck("sem repoPath \u2014 SEMGREP Agent precisa do reposit\xF3rio local");
    }
    const results = await this.scan(repoPath, this.timeoutMs);
    return mapSemgrepFindings({ saas: scope.target.name, runId: scope.runId, results });
  }
};

// ../agents/compliance/dist/index.js
import { readdir as readdir4, readFile as readFile5, stat as stat4 } from "fs/promises";
import { join as join5, relative as relative3 } from "path";
var SENSITIVE_FIELD = /(cpf|cnpj|cnis|\brg\b|senha|password|passwd|secret|processo|prontuario|prontuário|\bnis\b|\bpis\b|cart[aã]o|benef[ií]cio|sa[uú]de|health|biometr|genetic|gen[eé]tico|racial|etnia|religi|orienta[cç][aã]o|sexual|criminal|diagn[oó]stico)/i;
var PERSONAL_FIELD = /(nome|\bname\b|email|e-mail|\bmail\b|telefone|phone|celular|whatsapp|endere[cç]o|address|logradouro|\bcep\b|nascimento|birth|\bdob\b|\bidade\b|g[eê]nero|gender|foto|avatar|\bip\b|geoloc|latitude|longitude|documento|passaporte|matr[ií]cula)/i;
function classifyField(fieldName) {
  if (SENSITIVE_FIELD.test(fieldName)) return "sensivel";
  if (PERSONAL_FIELD.test(fieldName)) return "pessoal";
  return "comum";
}
function parsePrismaModels(schema) {
  const models = [];
  const modelRe = /model\s+(\w+)\s*\{([\s\S]*?)\}/g;
  let m;
  while ((m = modelRe.exec(schema)) !== null) {
    const name = m[1];
    const body = m[2];
    const fields = [];
    for (const line of body.split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith("//") || t.startsWith("@@")) continue;
      const field = t.split(/\s+/)[0];
      if (/^\w+$/.test(field)) fields.push(field);
    }
    models.push({ model: name, fields });
  }
  return models;
}
function buildInventory(models) {
  const out = [];
  for (const m of models) {
    const sensivel = [];
    const pessoal = [];
    for (const f of m.fields) {
      const c = classifyField(f);
      if (c === "sensivel") sensivel.push(f);
      else if (c === "pessoal") pessoal.push(f);
    }
    if (sensivel.length || pessoal.length) out.push({ model: m.model, sensivel, pessoal });
  }
  return out;
}
var OPERATORS = [
  { re: /^@?aws-sdk|^aws-sdk|^@aws-/, name: "AWS", purpose: "infraestrutura/cloud", international: true },
  { re: /^@google-cloud\/|^googleapis$|^firebase/, name: "Google Cloud/Firebase", purpose: "infraestrutura/cloud", international: true },
  { re: /^@azure\/|^@azure-/, name: "Microsoft Azure", purpose: "infraestrutura/cloud", international: true },
  { re: /^stripe$/, name: "Stripe", purpose: "pagamentos", international: true },
  { re: /^@?openai$|^openai$/, name: "OpenAI", purpose: "IA generativa (conte\xFAdo do usu\xE1rio)", international: true },
  { re: /^@anthropic-ai\//, name: "Anthropic", purpose: "IA generativa (conte\xFAdo do usu\xE1rio)", international: true },
  { re: /^@sentry\//, name: "Sentry", purpose: "monitoramento de erros", international: true },
  { re: /^@?posthog|^mixpanel|^@segment\/|^amplitude/, name: "Analytics (PostHog/Mixpanel/Segment/Amplitude)", purpose: "analytics/comportamento", international: true },
  { re: /^@supabase\//, name: "Supabase", purpose: "backend/banco de dados", international: true },
  { re: /^@vercel\//, name: "Vercel", purpose: "hospedagem/edge", international: true },
  { re: /^resend$|^@sendgrid\/|^mailgun|^nodemailer$|^postmark/, name: "E-mail transacional (Resend/SendGrid/Mailgun/Postmark)", purpose: "e-mail transacional", international: true },
  { re: /^twilio$/, name: "Twilio", purpose: "SMS/comunica\xE7\xE3o", international: true },
  { re: /^cloudinary$|^@cloudinary\//, name: "Cloudinary", purpose: "m\xEDdia/storage", international: true },
  { re: /^@datadog\/|^dd-trace$/, name: "Datadog", purpose: "observabilidade", international: true },
  { re: /^@upstash\//, name: "Upstash", purpose: "cache/fila (Redis/Kafka)", international: true },
  { re: /^@?mercadopago|^mercadopago/, name: "Mercado Pago", purpose: "pagamentos", international: false },
  { re: /^pg$|^mysql2?$|^prisma$|^@prisma\/|^mongoose$|^redis$|^ioredis$/, name: "Banco de dados (self-hosted)", purpose: "persist\xEAncia", international: false }
];
function detectOperators(packageJsonText) {
  let pkg;
  try {
    pkg = JSON.parse(packageJsonText);
  } catch {
    return [];
  }
  const names = /* @__PURE__ */ new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]);
  const seen = /* @__PURE__ */ new Map();
  for (const dep of names) {
    for (const op of OPERATORS) {
      if (op.re.test(dep)) {
        if (!seen.has(op.name)) seen.set(op.name, { name: op.name, purpose: op.purpose, international: op.international });
      }
    }
  }
  return Array.from(seen.values());
}
function stripMarkup(s) {
  return s.replace(/<[^>]*>/g, " ").replace(/\{[^{}]{0,120}\}/g, " ").replace(/&[a-z]+;/gi, " ").replace(/\s+/g, " ").trim();
}
var POLICY_TITLE = /pol[ií]tica de privacidade|privacy policy|aviso de privacidade/i;
var POLICY_PATH_HINT = /privac/i;
var POLICY_SIGNALS = [
  /transfer[êe]ncia internacional|internacional/i,
  /base legal|leg[ií]timo interesse|consentimento|art\.?\s*(?:7|9|11|33)\b/i,
  /titular(?:es)?\b/i,
  /reten[çc][ãa]o|prazo/i,
  /operador(?:es)?|sub-?processador|terceiros/i,
  /cookies?/i,
  /encarregad|dpo\b/i
];
function findPolicyDoc(files) {
  let best = null;
  for (const f of files) {
    if (!/\.(tsx|jsx|ts|js|md|mdx|html?)$/i.test(f.relPath)) continue;
    const pathHint = POLICY_PATH_HINT.test(f.relPath);
    if (!POLICY_TITLE.test(f.content) && !pathHint) continue;
    const text = stripMarkup(f.content);
    if (!POLICY_TITLE.test(text)) continue;
    const signals = POLICY_SIGNALS.reduce((n, re) => n + (re.test(text) ? 1 : 0), 0);
    if (signals < 3) continue;
    const score = signals + (pathHint ? 2 : 0) + Math.min(3, Math.floor(text.length / 1e3));
    if (!best || score > best.score) best = { relPath: f.relPath, text, score };
  }
  return best ? { relPath: best.relPath, text: best.text } : null;
}
var INTL_DISCLOSURE = /transfer[êe]ncia internacional|fora do (?:pa[ií]s|brasil)|outside brazil|other countries|estados unidos|\beua\b|internacional/i;
var INTL_DENIAL = new RegExp(
  [
    // "não" + (até ~30 chars, aceita acentos via [\s\S]) + termo de transferência ao exterior
    "n[\xE3a]o[\\s\\S]{0,30}?(?:transfer[\xEAe]ncia\\s+internacional|transfer\\w*\\b[\\s\\S]{0,20}?(?:exterior|fora do (?:pa[i\xED]s|brasil)))",
    // afirmação territorial: os dados permanecem/ficam/são mantidos/armazenados/hospedados NO Brasil
    "(?:permanec\\w+|fica\\w*|mantid\\w+|armazenad\\w+|hospedad\\w+)[\\s\\S]{0,25}?(?:no|em)\\s+brasil"
  ].join("|"),
  "i"
);
var OPERATOR_SYNONYMS = {
  AWS: ["aws", "amazon web services", "amazon"],
  "Google Cloud/Firebase": ["google", "firebase", "gcp", "google cloud"],
  "Microsoft Azure": ["azure", "microsoft"],
  Stripe: ["stripe"],
  OpenAI: ["openai", "open ai", "chatgpt", "gpt-"],
  Anthropic: ["anthropic", "claude"],
  Sentry: ["sentry"],
  "Analytics (PostHog/Mixpanel/Segment/Amplitude)": ["posthog", "mixpanel", "segment", "amplitude", "analytics"],
  Supabase: ["supabase"],
  Vercel: ["vercel"],
  "E-mail transacional (Resend/SendGrid/Mailgun/Postmark)": ["resend", "sendgrid", "mailgun", "postmark", "mail transacional", "e-mail transacional"],
  Twilio: ["twilio"],
  Cloudinary: ["cloudinary"],
  Datadog: ["datadog"],
  Upstash: ["upstash"],
  "Mercado Pago": ["mercado pago", "mercadopago"]
};
var NOT_A_SUBPROCESSOR = /* @__PURE__ */ new Set(["Banco de dados (self-hosted)"]);
function diffPolicyVsCode(policy, operators) {
  const text = policy.text.toLowerCase();
  const mentionsIntl = INTL_DISCLOSURE.test(policy.text);
  const deniesIntl = INTL_DENIAL.test(policy.text);
  const citesArt33Basis = /art\.?\s*33/i.test(policy.text);
  const internationalDenied = deniesIntl && !(mentionsIntl && citesArt33Basis);
  const internationalDisclosed = mentionsIntl && !internationalDenied;
  const hasInternationalOps = operators.some((o) => o.international);
  const undeclaredOperators = [];
  for (const op of operators) {
    if (NOT_A_SUBPROCESSOR.has(op.name)) continue;
    const syns = OPERATOR_SYNONYMS[op.name] ?? [op.name.toLowerCase()];
    const declared = syns.some((s) => text.includes(s));
    if (!declared) undeclaredOperators.push(op);
  }
  return { policyPath: policy.relPath, hasInternationalOps, internationalDisclosed, internationalDenied, undeclaredOperators };
}
var IGNORE_DIRS3 = /* @__PURE__ */ new Set(["node_modules", ".git", "dist", ".next", "coverage", ".turbo", "__tests__", "fracta-reports", ".worktrees", ".claude"]);
var TEXT_EXT = /* @__PURE__ */ new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts",
  ".json",
  ".prisma",
  ".env",
  ".yaml",
  ".yml",
  ".vue",
  ".svelte"
]);
var DOC_EXT = /* @__PURE__ */ new Set([".md", ".mdx", ".html", ".htm"]);
function extOf(relPath) {
  const dot = relPath.lastIndexOf(".");
  return dot < 0 ? "" : relPath.slice(dot).toLowerCase();
}
var MAX_FILE_BYTES = 2e6;
var SENSITIVE_TERM = /\b(cpf|cnpj|cnis|rg|senha|password|passwd|token|processo|prontuario|prontuário|nis|pis|cartao|cartão|beneficio|benefício)\b/i;
var SENSITIVE_TERM_GLOBAL = /\b(cpf|cnpj|cnis|rg|senha|password|passwd|token|processo|prontuario|prontuário|nis|pis|cartao|cartão|beneficio|benefício)\b/gi;
var LOG_CALL = /(?:console\.(?:log|error|info|warn|debug)|(?:this\.)?logger\.\w+)\s*\(/i;
function stripStringLiterals(s) {
  return s.replace(/`(?:\\.|\$\{[^}]*\}|[^`\\])*`/g, " ").replace(/'(?:\\.|[^'\\])*'/g, " ").replace(/"(?:\\.|[^"\\])*"/g, " ").replace(/[`'"][^`'"]*$/g, " ");
}
var HASHING_LIBS = ["bcrypt", "bcryptjs", "argon2", "@node-rs/argon2", "scrypt"];
var PASSWORD_TERM = /\bpassword|senha|passwd\b/i;
var DB_WRITE = /\b(create|createMany|insert|insertInto|save|update|upsert|INSERT\s+INTO)\b/i;
var PRISMA_FIND = /\.(findMany|findFirst)\s*\(/;
var TENANT_SCOPE = /tenantId|ownerId|accountId|orgId/i;
var TLS_SIGNAL = /https:\/\/|\bsecure\s*:\s*true\b|helmet|hsts|strict-transport-security|forceSSL|requireHTTPS/i;
var ComplianceAgent = class {
  name = "COMPLIANCE Agent";
  category = "compliance";
  concurrency = 1;
  timeoutMs = 6e4;
  async run(scope) {
    const repoPath = scope.target.repoPath;
    if (!repoPath) {
      throw new SkippedCheck("sem repoPath \u2014 ComplianceAgent precisa do reposit\xF3rio local (read-only)");
    }
    const findings = [];
    const files = await this.collectFiles(repoPath);
    let mentionsSensitiveAnywhere = false;
    let hasTlsSignal = false;
    let hasPasswordWrite = false;
    for (const file of files) {
      if (DOC_EXT.has(extOf(file.relPath))) continue;
      const lines = file.content.split(/\r?\n/);
      if (SENSITIVE_TERM.test(file.content)) mentionsSensitiveAnywhere = true;
      if (TLS_SIGNAL.test(file.content)) hasTlsSignal = true;
      if (PASSWORD_TERM.test(file.content) && DB_WRITE.test(file.content)) {
        hasPasswordWrite = true;
      }
      const fileMentionsSensitive = SENSITIVE_TERM.test(file.content);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNo = i + 1;
        if (LOG_CALL.test(line)) {
          const hit = this.matchSensitiveLog(line);
          if (hit) {
            findings.push(this.sensitiveInLog(scope, file.relPath, lineNo, hit));
          }
        }
        if (fileMentionsSensitive && PRISMA_FIND.test(line)) {
          if (!this.hasTenantScopeNearby(lines, i)) {
            findings.push(this.tenantIsolation(scope, file.relPath, lineNo));
          }
        }
      }
    }
    if (hasPasswordWrite && !this.hasHashingLibInAnyPackageJson(files)) {
      findings.push(this.passwordNoHashing(scope));
    }
    if (mentionsSensitiveAnywhere && !hasTlsSignal) {
      findings.push(this.encryptionUnclear(scope));
    }
    const prismaText = files.filter((f) => f.relPath.endsWith(".prisma")).map((f) => f.content).join("\n");
    if (prismaText.trim()) {
      const inventory = buildInventory(parsePrismaModels(prismaText));
      if (inventory.length) findings.push(this.dataInventory(scope, inventory));
    }
    const opMap = /* @__PURE__ */ new Map();
    for (const f of files) {
      if (f.relPath === "package.json" || f.relPath.endsWith("/package.json")) {
        for (const op of detectOperators(f.content)) if (!opMap.has(op.name)) opMap.set(op.name, op);
      }
    }
    if (opMap.size) {
      const operators = Array.from(opMap.values());
      findings.push(this.operatorsMapping(scope, operators));
      const policy = findPolicyDoc(files);
      if (policy) {
        const div = diffPolicyVsCode(policy, operators);
        if (div.hasInternationalOps) {
          if (div.internationalDenied) {
            findings.push(this.intlTransferContradicted(scope, policy.relPath, operators.filter((o) => o.international)));
          } else if (!div.internationalDisclosed) {
            findings.push(this.intlTransferUndisclosed(scope, policy.relPath, operators.filter((o) => o.international)));
          }
        }
        if (div.undeclaredOperators.length) {
          findings.push(this.operatorsUndeclared(scope, policy.relPath, div.undeclaredOperators));
        }
      } else {
        findings.push(this.policyNotFound(scope, operators));
      }
    }
    return findings;
  }
  // -------------------------------------------------------------------------
  // Check 7 — divergência política×código (materializa o diferencial LGPD-nativo)
  // -------------------------------------------------------------------------
  intlTransferContradicted(scope, policyPath, intlOps) {
    const rule = "lgpd-policy-intl-contradicted";
    const names = intlOps.map((o) => o.name).join(", ");
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "medium",
      // mais grave que a omissão (low): a política CONTRADIZ o código
      confidence: "low",
      // heurística de negação — pede confirmação humana antes de agir
      title: `Transfer\xEAncia internacional NEGADA na pol\xEDtica, mas o c\xF3digo a realiza (Art. 33)`,
      description: `CONFERI A POL\xCDTICA PUBLICADA CONTRA O C\xD3DIGO e encontrei uma CONTRADI\xC7\xC3O DIRETA. A pol\xEDtica de privacidade (${policyPath}) AFIRMA que N\xC3O h\xE1 transfer\xEAncia internacional (ou que os dados permanecem no Brasil), mas o c\xF3digo usa operadores que processam dados fora do Brasil (${names}) \u2014 o que configura TRANSFER\xCANCIA INTERNACIONAL (Art. 33 da LGPD). Uma pol\xEDtica que NEGA o que o c\xF3digo faz \xE9 pior que uma omissa: induz o titular a erro. HEUR\xCDSTICA \u2014 a detec\xE7\xE3o de nega\xE7\xE3o \xE9 aproximada; CONFIRME o texto da pol\xEDtica antes de agir (a declara\xE7\xE3o pode estar segmentada).`,
      evidence: `Pol\xEDtica conferida: ${policyPath}. A pol\xEDtica NEGA transfer\xEAncia internacional / afirma reten\xE7\xE3o no Brasil, mas h\xE1 operadores internacionais no c\xF3digo: ${names}.`,
      recommendation: `Corrija a contradi\xE7\xE3o: ou (a) a Pol\xEDtica de Privacidade passa a DECLARAR a transfer\xEAncia internacional ancorada numa hip\xF3tese do Art. 33 (cl\xE1usulas-padr\xE3o da ANPD, pa\xEDs adequado, etc.) e lista os operadores no exterior (${names}); ou (b) elimine a transfer\xEAncia internacional de fato (operador nacional/self-hosted). Manter a nega\xE7\xE3o enquanto o c\xF3digo transfere exp\xF5e o controlador a san\xE7\xE3o por informa\xE7\xE3o enganosa ao titular (Art. 6\xBA, VI \u2014 transpar\xEAncia).`,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  intlTransferUndisclosed(scope, policyPath, intlOps) {
    const rule = "lgpd-policy-intl-undisclosed";
    const names = intlOps.map((o) => o.name).join(", ");
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "low",
      confidence: "low",
      // heurística: a política pode declarar em outra página/genericamente
      title: `Transfer\xEAncia internacional n\xE3o declarada na pol\xEDtica (Art. 33)`,
      description: `CONFERI A POL\xCDTICA PUBLICADA CONTRA O C\xD3DIGO. O projeto usa operadores que processam dados fora do Brasil (${names}), o que configura TRANSFER\xCANCIA INTERNACIONAL (Art. 33 da LGPD), mas a pol\xEDtica de privacidade encontrada (${policyPath}) n\xE3o cont\xE9m nenhuma men\xE7\xE3o a transfer\xEAncia internacional / dados fora do Brasil. HEUR\xCDSTICA \u2014 a declara\xE7\xE3o pode estar em outra p\xE1gina; confirme antes de agir.`,
      evidence: `Pol\xEDtica conferida: ${policyPath}. Operadores internacionais no c\xF3digo: ${names}. Nenhuma men\xE7\xE3o a "transfer\xEAncia internacional"/"fora do Brasil" na pol\xEDtica.`,
      recommendation: "Declare a transfer\xEAncia internacional na Pol\xEDtica de Privacidade, ancorada numa hip\xF3tese do Art. 33 (cl\xE1usulas-padr\xE3o da ANPD, pa\xEDs com n\xEDvel adequado, etc.) e liste os operadores no exterior. Este \xE9 um requisito de transpar\xEAncia, n\xE3o opcional.",
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  operatorsUndeclared(scope, policyPath, ops) {
    const rule = "lgpd-policy-operators-undeclared";
    const names = ops.map((o) => o.name).join(", ");
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "low",
      confidence: "low",
      // conservador: só acusa quando NEM o nome NEM sinônimos aparecem na política
      title: `Operadores no c\xF3digo ausentes da pol\xEDtica de privacidade`,
      description: `CONFERI A POL\xCDTICA PUBLICADA CONTRA O C\xD3DIGO. Estes operadores/sub-processadores s\xE3o usados pelo projeto (deps) mas o nome deles n\xE3o aparece na pol\xEDtica encontrada (${policyPath}):
` + ops.map((o) => `\u2022 ${o.name} (${o.purpose})${o.international ? " \u2014 transfer\xEAncia internacional" : ""}`).join("\n") + '\n\nHEUR\xCDSTICA CONSERVADORA \u2014 a pol\xEDtica pode descrev\xEA-los genericamente (ex.: "provedores de nuvem"). Reveja se cada tratamento est\xE1 transparente ao titular (Art. 9\xBA).',
      evidence: `Pol\xEDtica conferida: ${policyPath}. Operadores n\xE3o citados nominalmente: ${names}.`,
      recommendation: "Liste nominalmente os operadores/sub-processadores na Pol\xEDtica de Privacidade (Art. 9\xBA/Art. 39), com finalidade e, quando no exterior, a base de transfer\xEAncia internacional. Isso torna o tratamento transparente e verific\xE1vel pelo titular.",
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  policyNotFound(scope, operators) {
    const rule = "lgpd-policy-not-found";
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "info",
      title: `Diverg\xEAncia pol\xEDtica\xD7c\xF3digo n\xE3o verific\xE1vel \u2014 pol\xEDtica n\xE3o localizada no reposit\xF3rio`,
      description: `Detectei ${operators.length} operador(es)/sub-processador(es) no c\xF3digo, mas n\xE3o localizei uma Pol\xEDtica de Privacidade dentro do reposit\xF3rio para conferir automaticamente o que o c\xF3digo faz contra o que a pol\xEDtica declara. HONESTIDADE: n\xE3o afirmo que a pol\xEDtica inexiste \u2014 ela pode estar hospedada fora do repo (CMS, site institucional). A confer\xEAncia pol\xEDtica\xD7c\xF3digo n\xE3o p\xF4de ser executada.`,
      evidence: `Operadores no c\xF3digo: ${operators.map((o) => o.name).join(", ")}. Nenhum documento de pol\xEDtica de privacidade encontrado no reposit\xF3rio.`,
      recommendation: "Para permitir a confer\xEAncia autom\xE1tica, versione a Pol\xEDtica de Privacidade no reposit\xF3rio (p\xE1gina ou markdown). Independentemente disso, garanta que a pol\xEDtica publicada declare os operadores e a transfer\xEAncia internacional (Art. 9\xBA/Art. 33).",
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  // -------------------------------------------------------------------------
  // Check 5 — inventário de dados pessoais ancorado no schema (rascunho de ROPA)
  // -------------------------------------------------------------------------
  dataInventory(scope, inv) {
    const rule = "lgpd-data-inventory";
    const totalSens = inv.reduce((n, e) => n + e.sensivel.length, 0);
    const lines = inv.map((e) => {
      const parts = [
        e.sensivel.length ? `sens\xEDvel: ${e.sensivel.join(", ")}` : "",
        e.pessoal.length ? `pessoal: ${e.pessoal.join(", ")}` : ""
      ].filter(Boolean);
      return `\u2022 ${e.model} \u2192 ${parts.join(" | ")}`;
    });
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "info",
      title: `Invent\xE1rio de dados pessoais ancorado no schema (rascunho de ROPA) \u2014 ${inv.length} modelos, ${totalSens} campos sens\xEDveis`,
      description: "Li o schema Prisma e montei o esqueleto de um INVENT\xC1RIO DE DADOS / ROPA (Art. 37) ancorado no seu c\xF3digo \u2014 n\xE3o num formul\xE1rio auto-declarado. Modelos com dado pessoal:\n" + lines.join("\n") + "\n\nHeur\xEDstica determin\xEDstica por nome de campo (zero IA) \u2014 pode ter falso-positivo/negativo. Cada tratamento ainda precisa de finalidade, base legal e reten\xE7\xE3o (o julgamento jur\xEDdico).",
      evidence: `${inv.length} modelos com dado pessoal; ${totalSens} campos classificados como sens\xEDveis (Art. 5\xBA, II).`,
      recommendation: "Use isto como ponto de partida do ROPA: para cada modelo/finalidade, defina base legal (Art. 7\xBA/11), prazo de reten\xE7\xE3o (Art. 15/16) e compartilhamentos. Dado sens\xEDvel exige base do Art. 11 e cuidado agravado.",
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  // -------------------------------------------------------------------------
  // Check 6 — operadores/sub-processadores + transferência internacional (Art. 33)
  // -------------------------------------------------------------------------
  operatorsMapping(scope, ops) {
    const rule = "lgpd-operators-transfer";
    const intl = ops.filter((o) => o.international);
    const lines = ops.map((o) => `\u2022 ${o.name} (${o.purpose})${o.international ? " \u2014 transfer\xEAncia internacional" : ""}`);
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "info",
      title: `Operadores/sub-processadores detectados no c\xF3digo \u2014 ${ops.length} (${intl.length} com transfer\xEAncia internacional)`,
      description: "Mapeei operadores/sub-processadores pelas depend\xEAncias do projeto (Art. 39). Cada um trata dado pessoal por sua conta e precisa de contrato (DPA):\n" + lines.join("\n") + (intl.length ? `

\u26A0\uFE0F ${intl.length} implicam TRANSFER\xCANCIA INTERNACIONAL de dados (Art. 33) \u2014 que precisa ser declarada na pol\xEDtica e ancorada numa hip\xF3tese (cl\xE1usulas-padr\xE3o da ANPD, pa\xEDs adequado, etc.).` : "") + "\n\nHeur\xEDstica por nome de pacote \u2014 confirme a stack real e os contratos.",
      evidence: `Operadores: ${ops.map((o) => o.name).join(", ")}. Transfer\xEAncia internacional: ${intl.map((o) => o.name).join(", ") || "nenhuma detectada"}.`,
      recommendation: "Garanta um DPA com cada operador (Art. 39), liste os sub-processadores, e declare a transfer\xEAncia internacional na Pol\xEDtica de Privacidade ancorada numa hip\xF3tese do Art. 33.",
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  // -------------------------------------------------------------------------
  // Check 1 — dado sensível em log (risco-chave LGPD)
  // SANITIZAÇÃO: nunca ecoa o valor logado. A evidence é só `relPath:line`
  // mais o termo sensível que casou (nome de variável/chave), jamais o conteúdo.
  // -------------------------------------------------------------------------
  matchSensitiveLog(line) {
    const code = stripStringLiterals(line);
    const callIdxCode = code.search(LOG_CALL);
    if (callIdxCode < 0) return null;
    const rawParen = line.indexOf("(", line.search(LOG_CALL));
    if (rawParen < 0) return null;
    const rawArgs = this.extractCallArgs(line, rawParen);
    const interpolations = Array.from(rawArgs.matchAll(/\$\{([^}]*)\}/g)).map((m) => m[1]).join(" ");
    const codeArgs = stripStringLiterals(rawArgs);
    const adjacentLabels = Array.from(rawArgs.matchAll(/([\p{L}]+)\s*[:=]\s*\$\{/gu)).map((m) => m[1]).join(" ");
    const haystack = `${interpolations} ${codeArgs} ${adjacentLabels}`;
    const matches = haystack.match(SENSITIVE_TERM_GLOBAL);
    if (!matches || matches.length === 0) return null;
    const term = Array.from(new Set(matches.map((m) => m.toLowerCase()))).join(", ");
    return { relPath: "", line: 0, term };
  }
  /** Argumentos de uma chamada a partir do '(' de abertura (parênteses balanceados na linha). */
  extractCallArgs(line, openParen) {
    let depth = 0;
    for (let i = openParen; i < line.length; i++) {
      const c = line[i];
      if (c === "(") depth++;
      else if (c === ")") {
        depth--;
        if (depth === 0) return line.slice(openParen + 1, i);
      }
    }
    return line.slice(openParen + 1);
  }
  sensitiveInLog(scope, relPath, line, hit) {
    const rule = `sensitive-in-log:${relPath}:${line}`;
    const proposedFix = {
      description: "Remova o dado sens\xEDvel do log ou aplique mascaramento/reda\xE7\xE3o antes de logar (ex.: logar apenas um id de correla\xE7\xE3o, ou mascarar CPF como ***.***.***-**). Prefira um logger estruturado com reda\xE7\xE3o autom\xE1tica de campos sens\xEDveis.",
      riskOfApplying: "PROPOSTA \u2014 n\xE3o aplicada. Alterar logs pode reduzir a observabilidade usada em debugging/auditoria; confirme com a equipe que nenhum fluxo depende daquele valor em texto plano antes de remover."
    };
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule, location: relPath }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "high",
      title: `Poss\xEDvel dado sens\xEDvel em log: ${relPath}:${line}`,
      description: `Dado sens\xEDvel pode estar sendo gravado em log em texto plano (LGPD). A chamada de log nesta linha referencia um identificador sens\xEDvel (termo casado: ${hit.term}). Dados como CPF/CNIS/dados previdenci\xE1rios e processos criminais s\xE3o DADO SENS\xCDVEL sob a LGPD (art. 5\xBA, II), com responsabiliza\xE7\xE3o agravada se vazados via logs.`,
      // SANITIZADO: apenas arquivo:linha + termo. Nunca o valor logado.
      evidence: `${relPath}:${line} (termo sens\xEDvel: ${hit.term})`,
      recommendation: "Nunca registre dado sens\xEDvel em texto plano. Mascare ou remova o valor do log (LGPD art. 6\xBA \u2014 seguran\xE7a/preven\xE7\xE3o; art. 46 \u2014 medidas de seguran\xE7a). Dado previdenci\xE1rio/criminal \xE9 dado sens\xEDvel: o vazamento por log acarreta responsabiliza\xE7\xE3o agravada do controlador.",
      proposedFix,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  // -------------------------------------------------------------------------
  // Check 2 — senhas sem hashing
  // -------------------------------------------------------------------------
  /** Procura uma lib de hashing em QUALQUER package.json do repo (monorepo-aware). */
  hasHashingLibInAnyPackageJson(files) {
    for (const f of files) {
      if (f.relPath !== "package.json" && !f.relPath.endsWith("/package.json")) continue;
      let pkg;
      try {
        pkg = JSON.parse(f.content);
      } catch {
        continue;
      }
      const deps = { ...pkg.dependencies ?? {}, ...pkg.devDependencies ?? {} };
      if (HASHING_LIBS.some((lib) => lib in deps)) return true;
    }
    return false;
  }
  passwordNoHashing(scope) {
    const rule = "password-no-hashing";
    const proposedFix = {
      description: "Use uma fun\xE7\xE3o de hashing forte para senhas (ex.: argon2 ou bcrypt) antes de persistir. Nunca armazene senha em texto plano nem com hash revers\xEDvel/MD5/SHA1.",
      command: "npm install argon2",
      riskOfApplying: "PROPOSTA \u2014 n\xE3o aplicada. Requer migra\xE7\xE3o das senhas existentes (re-hash no pr\xF3ximo login) e ajuste do fluxo de verifica\xE7\xE3o. Aplicar sem cuidado pode travar logins. CONFIRMA\xC7\xC3O HUMANA obrigat\xF3ria: a heur\xEDstica \xE9 conservadora e pode haver hashing feito por um servi\xE7o externo (ex.: provider de auth) n\xE3o vis\xEDvel no package.json."
    };
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "high",
      confidence: "low",
      // heurística conservadora (hashing pode ser externo) — avisa, não derruba
      title: "Poss\xEDvel armazenamento de senha sem hashing",
      description: `O reposit\xF3rio aparenta ter autentica\xE7\xE3o (men\xE7\xE3o a senha/password pr\xF3xima de uma escrita/cria\xE7\xE3o no banco), mas nenhuma biblioteca de hashing (${HASHING_LIBS.join(", ")}) consta nas depend\xEAncias do package.json. Senhas sem hashing forte violam medidas de seguran\xE7a esperadas pela LGPD (art. 46). HEUR\xCDSTICA CONSERVADORA \u2014 exige confirma\xE7\xE3o humana, pois o hashing pode ocorrer fora deste reposit\xF3rio (provider de auth gerenciado).`,
      evidence: "package.json sem bcrypt/bcryptjs/argon2/@node-rs/argon2/scrypt + escrita de senha detectada no c\xF3digo.",
      recommendation: "Confirme manualmente como as senhas s\xE3o armazenadas. Se forem persistidas por este servi\xE7o, aplique argon2/bcrypt. LGPD art. 46 exige medidas t\xE9cnicas adequadas para proteger dados pessoais \u2014 credenciais comprometidas costumam expor dado sens\xEDvel dos titulares.",
      proposedFix,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  // -------------------------------------------------------------------------
  // Check 3 — isolamento de tenant em arquivos com dado sensível (heurística)
  // -------------------------------------------------------------------------
  hasTenantScopeNearby(lines, idx) {
    const end = Math.min(lines.length, idx + 7);
    for (let i = idx; i < end; i++) {
      if (TENANT_SCOPE.test(lines[i])) return true;
    }
    return false;
  }
  tenantIsolation(scope, relPath, line) {
    const rule = `tenant-isolation-sensitive:${relPath}:${line}`;
    const proposedFix = {
      description: "Adicione um filtro de tenant/owner no `where` da query (ex.: `where: { tenantId: user.tenantId, ... }`) para garantir que apenas dados do titular/organiza\xE7\xE3o correta sejam retornados.",
      riskOfApplying: "PROPOSTA \u2014 n\xE3o aplicada. \xC9 uma HEUR\xCDSTICA: a query pode j\xE1 ser legitimamente global (ex.: rota administrativa) ou o escopo pode ser aplicado em outra camada (RLS, middleware). Adicionar where indevido pode esconder dados esperados. Revis\xE3o humana obrigat\xF3ria."
    };
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule, location: relPath }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "low",
      confidence: "low",
      // heurística p/ revisão humana (pode ser RLS/middleware ou query global)
      title: `Query sem escopo de tenant em arquivo com dado sens\xEDvel: ${relPath}:${line}`,
      description: "HEUR\xCDSTICA PARA REVIS\xC3O HUMANA. Uma chamada Prisma findMany/findFirst nesta linha n\xE3o referencia tenantId/ownerId/accountId/orgId nas linhas pr\xF3ximas, e o arquivo manipula dado sens\xEDvel. Cruza com a verifica\xE7\xE3o de tenant do StackAgent, mas aqui restrita a arquivos que tocam dado sens\xEDvel \u2014 onde a falta de isolamento implica exposi\xE7\xE3o de DADO SENS\xCDVEL sob a LGPD (responsabiliza\xE7\xE3o agravada). Pode ser falso positivo se o escopo for aplicado por RLS/middleware ou se a query for legitimamente global.",
      evidence: `${relPath}:${line} \u2014 findMany/findFirst sem where com tenantId/ownerId/accountId/orgId nas proximidades.`,
      recommendation: "Verifique manualmente se a query \xE9 multi-tenant. Se for, escope por tenant/owner do usu\xE1rio autenticado. LGPD: vazamento cross-tenant de dado sens\xEDvel (previdenci\xE1rio/criminal/CPF) gera responsabiliza\xE7\xE3o agravada do controlador.",
      proposedFix,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  // -------------------------------------------------------------------------
  // Check 4 — criptografia em trânsito/repouso não evidenciada (heurística)
  // -------------------------------------------------------------------------
  encryptionUnclear(scope) {
    const rule = "encryption-unclear";
    const proposedFix = {
      description: "Garanta TLS/HTTPS de ponta a ponta (HSTS via helmet, cookies com `secure: true`, redirecionamento http\u2192https) e avalie criptografia em repouso para os campos sens\xEDveis.",
      riskOfApplying: "PROPOSTA \u2014 n\xE3o aplicada. \xC9 uma HEUR\xCDSTICA conservadora: TLS pode estar terminado no proxy/load balancer (nginx, Cloudflare) fora deste reposit\xF3rio. For\xE7ar HTTPS/HSTS incorretamente pode quebrar ambientes de dev. Verifica\xE7\xE3o humana obrigat\xF3ria."
    };
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: "low",
      confidence: "low",
      // heurística conservadora (TLS pode terminar no proxy/LB) — avisa, não derruba
      title: "Criptografia em tr\xE2nsito/repouso n\xE3o evidenciada",
      description: "O reposit\xF3rio manipula dado sens\xEDvel, mas n\xE3o foi encontrado sinal de TLS/HTTPS for\xE7ado (sem `https`, sem cookie `secure: true`, sem HSTS/helmet) no c\xF3digo. HEUR\xCDSTICA CONSERVADORA \u2014 requer verifica\xE7\xE3o humana: a termina\xE7\xE3o TLS pode ocorrer em proxy/LB (nginx, Cloudflare) fora deste reposit\xF3rio. Sob a LGPD (art. 46), dados sens\xEDveis (previdenci\xE1rio/criminal/CPF) exigem medidas de seguran\xE7a como criptografia em tr\xE2nsito e, quando aplic\xE1vel, em repouso.",
      evidence: "Reposit\xF3rio com dado sens\xEDvel e sem evid\xEAncia em c\xF3digo de TLS/HTTPS/secure cookie/HSTS.",
      recommendation: "Confirme manualmente que todo tr\xE1fego \xE9 HTTPS (TLS no app ou no proxy) e que cookies de sess\xE3o usam `secure`/`httpOnly`. Avalie criptografia em repouso para campos sens\xEDveis. LGPD art. 46 exige medidas t\xE9cnicas proporcionais ao risco \u2014 dado sens\xEDvel eleva o padr\xE3o exigido.",
      proposedFix,
      createdAt: /* @__PURE__ */ new Date()
    };
  }
  // -------------------------------------------------------------------------
  // File walking (espelha o DocsAgent: ignora IGNORE_DIRS, tolera erros por arquivo)
  // -------------------------------------------------------------------------
  async collectFiles(repoPath) {
    const files = [];
    await this.walkDir(repoPath, repoPath, files);
    return files;
  }
  async walkDir(dir, baseDir, files) {
    let entries;
    try {
      entries = await readdir4(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORE_DIRS3.has(entry)) continue;
      const fullPath = join5(dir, entry);
      try {
        const info = await stat4(fullPath);
        if (info.isDirectory()) {
          await this.walkDir(fullPath, baseDir, files);
        } else if (this.isTextFile(entry) && info.size <= MAX_FILE_BYTES) {
          const content = await readFile5(fullPath, "utf-8");
          files.push({
            relPath: relative3(baseDir, fullPath).replace(/\\/g, "/"),
            content
          });
        }
      } catch {
      }
    }
  }
  isTextFile(name) {
    if (name === "package.json") return true;
    if (name.startsWith(".env")) return true;
    const dot = name.lastIndexOf(".");
    if (dot < 0) return false;
    const ext = name.slice(dot).toLowerCase();
    return TEXT_EXT.has(ext) || DOC_EXT.has(ext);
  }
};

// ../skills/nestjs/dist/index.js
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
    if (!target.stack?.includes("nestjs")) return findings;
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
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `nestjs-swagger-exposed:${path}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
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
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `nestjs-health-leak:${path}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
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

// ../skills/prisma/dist/index.js
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
    if (!target.stack?.includes("prisma")) return findings;
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

// ../skills/supabase/dist/index.js
var COMMON_TABLES = [
  "users",
  "profiles",
  "accounts",
  "customers",
  "orders",
  "invoices",
  "subscriptions",
  "messages",
  "notifications",
  "logs"
];
var COMMON_BUCKETS = ["avatars", "public", "uploads", "documents", "attachments"];
function looksLikeSupabaseError(body) {
  return /\b(PGRST|JWT expired|No API key|Invalid API key|permission denied for table)\b/i.test(body);
}
var SupabaseSkill = class {
  name = "Supabase Skill";
  category = "security";
  concurrency = 2;
  timeoutMs = 6e4;
  anonKey;
  constructor(options = {}) {
    this.anonKey = options.anonKey ?? process.env.SUPABASE_ANON_KEY;
  }
  async run(scope) {
    const findings = [];
    const { target } = scope;
    if (!target.stack?.includes("supabase")) return findings;
    const client = new FractaHttpClient(target.url);
    const ignore = target.ignore ?? [];
    await this.probeRestRoot(scope, client, findings, ignore);
    await this.probeStorage(scope, client, findings, ignore);
    if (this.anonKey) {
      await this.probeAnonReads(scope, client, findings, ignore);
    }
    return findings;
  }
  async probeRestRoot(scope, client, findings, ignore) {
    const path = "/rest/v1/";
    if (ignore.some((i) => path.startsWith(i))) return;
    try {
      const res = await client.request(path, { timeoutMs: 4e3 });
      if (res.status === 200 && res.raw.length > 10) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `supabase-rest-root:${path}`, location: path }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "medium",
          title: `Supabase REST root acess\xEDvel sem chave: ${path}`,
          description: `${path} respondeu 200 sem header apikey/Authorization. O REST root exp\xF5e a estrutura de tabelas e prepara IDOR e enumera\xE7\xE3o.`,
          endpoint: path,
          evidence: `GET ${path} \u2192 HTTP 200 (${res.raw.length} bytes)
${res.raw.substring(0, 200).replace(/\s+/g, " ").trim()}`,
          recommendation: "Coloque um WAF/edge function rejeitando requests sem apikey, ou use Supabase pr\xF3ximo ao banco com Row Level Security ativada em TODAS as tabelas \u2014 RLS off + REST p\xFAblico = banco aberto.",
          references: [
            "https://supabase.com/docs/guides/database/postgres/row-level-security",
            "https://supabase.com/docs/guides/api"
          ],
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    } catch {
    }
  }
  async probeStorage(scope, client, findings, ignore) {
    for (const bucket of COMMON_BUCKETS) {
      const path = `/storage/v1/object/list/${bucket}`;
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, {
          method: "POST",
          body: { prefix: "", limit: 5 },
          timeoutMs: 4e3
        });
        if (res.status === 200 && res.raw.length > 5 && !looksLikeSupabaseError(res.raw)) {
          findings.push({
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `supabase-storage-list:${bucket}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
            severity: "high",
            title: `Bucket Storage list\xE1vel sem auth: ${bucket}`,
            description: `POST em ${path} retornou listagem (HTTP 200, ${res.raw.length} bytes) sem credenciais. Bucket "${bucket}" permite enumera\xE7\xE3o de objetos por qualquer um.`,
            endpoint: path,
            evidence: `POST ${path} \u2192 HTTP 200
${res.raw.substring(0, 200).replace(/\s+/g, " ").trim()}`,
            recommendation: "Restrinja listagem em buckets p\xFAblicos \u2014 apenas o GET direto a um path conhecido deve ser permitido:\n```sql\ncreate policy \"no public listing\" on storage.objects\n  for select using (auth.role() = 'authenticated');\n```",
            references: ["https://supabase.com/docs/guides/storage/security/access-control"],
            createdAt: /* @__PURE__ */ new Date()
          });
          return;
        }
      } catch {
      }
    }
  }
  async probeAnonReads(scope, client, findings, ignore) {
    const anonClient = client.withHeaders({
      apikey: this.anonKey,
      Authorization: `Bearer ${this.anonKey}`
    });
    for (const table of COMMON_TABLES) {
      const path = `/rest/v1/${table}?select=*&limit=3`;
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await anonClient.request(path, { timeoutMs: 4e3 });
        if (res.status !== 200) continue;
        try {
          const data = JSON.parse(res.raw);
          if (Array.isArray(data) && data.length > 0) {
            findings.push({
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `supabase-rls-off:${table}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
              severity: "critical",
              title: `RLS off \u2014 tabela "${table}" lida com anon key`,
              description: `GET ${path} retornou ${data.length} linhas usando apenas a anon key. A tabela "${table}" est\xE1 com Row Level Security desativada ou com policy permissiva \u2014 qualquer cliente do frontend (e qualquer atacante) l\xEA esses dados.`,
              endpoint: path,
              evidence: `GET ${path} \u2192 200, ${data.length} rows
${res.raw.substring(0, 200).replace(/\s+/g, " ").trim()}`,
              recommendation: "Habilite RLS e crie policies por user:\n```sql\nalter table public." + table + ' enable row level security;\ncreate policy "user reads own row" on public.' + table + "\n  for select using (auth.uid() = user_id);\n```",
              references: [
                "https://supabase.com/docs/guides/database/postgres/row-level-security",
                "https://cwe.mitre.org/data/definitions/284.html"
              ],
              createdAt: /* @__PURE__ */ new Date()
            });
          }
        } catch {
        }
      } catch {
      }
    }
  }
};

// ../reporter/dist/index.js
import { mkdir, writeFile } from "fs/promises";
import { join as join6 } from "path";
var LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note"
};
function slug(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}
function ruleIdFor(f) {
  return `${f.category}/${slug(f.agent)}`;
}
function toSarif(report, opts = {}) {
  const findings = report.findings ?? [];
  const rules = /* @__PURE__ */ new Map();
  const results = findings.map((f) => {
    const id = ruleIdFor(f);
    if (!rules.has(id)) {
      rules.set(id, {
        id,
        name: `${f.agent} (${f.category})`,
        shortDescription: { text: `Achados de ${f.agent}` },
        defaultConfiguration: { level: LEVEL[f.severity] }
      });
    }
    const uri = f.location?.file?.trim() || f.endpoint?.trim() || report.target;
    const region = f.location?.line ? { startLine: f.location.line } : void 0;
    return {
      ruleId: id,
      level: LEVEL[f.severity],
      message: { text: f.description ? `${f.title} \u2014 ${f.description}` : f.title },
      locations: [{ physicalLocation: { artifactLocation: { uri }, ...region ? { region } : {} } }],
      partialFingerprints: { fractaFindingId: f.id }
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Fracta",
            version: opts.toolVersion ?? "0.0.0",
            informationUri: "https://fracta.pro",
            rules: [...rules.values()]
          }
        },
        results
      }
    ]
  };
}
var OWASP_2021 = [
  { id: "A01", name: "Broken Access Control" },
  { id: "A02", name: "Cryptographic Failures" },
  { id: "A03", name: "Injection" },
  { id: "A04", name: "Insecure Design" },
  { id: "A05", name: "Security Misconfiguration" },
  { id: "A06", name: "Vulnerable and Outdated Components" },
  { id: "A07", name: "Identification and Authentication Failures" },
  { id: "A08", name: "Software and Data Integrity Failures" },
  { id: "A09", name: "Security Logging and Monitoring Failures" },
  { id: "A10", name: "Server-Side Request Forgery" }
];
var CWE_TO_OWASP = {
  "639": "A01",
  "285": "A01",
  "200": "A01",
  "352": "A01",
  "862": "A01",
  "347": "A02",
  "311": "A02",
  "319": "A02",
  "79": "A03",
  "89": "A03",
  "94": "A03",
  "78": "A03",
  "77": "A03",
  "362": "A04",
  "16": "A05",
  "693": "A05",
  "942": "A05",
  "208": "A07",
  "287": "A07",
  "307": "A07",
  "798": "A07",
  "918": "A10"
};
var APICAT_TO_OWASP = {
  "0xa1": "A01",
  "0xa3": "A01",
  "0xa5": "A01",
  "0xa2": "A07"
};
var SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function classifyOwasp(finding) {
  const hay = [finding.title, finding.description, ...finding.references ?? []].join(" ");
  const explicit = hay.match(/\bA(\d{2}):2021\b/i);
  if (explicit) return `A${explicit[1]}`;
  const cwe = hay.match(/(?:CWE-|definitions\/)(\d+)/i);
  if (cwe && CWE_TO_OWASP[cwe[1]]) return CWE_TO_OWASP[cwe[1]];
  const api = hay.match(/0xa[0-9]/i);
  if (api && APICAT_TO_OWASP[api[0].toLowerCase()]) return APICAT_TO_OWASP[api[0].toLowerCase()];
  if (finding.category === "deps") return "A06";
  if (finding.category === "compliance") return "LGPD";
  return "unclassified";
}
var EXTRA_NAMES = {
  LGPD: "Privacidade / LGPD (fora do OWASP Top 10)",
  unclassified: "N\xE3o classificado"
};
function buildScorecard(findings) {
  const acc = /* @__PURE__ */ new Map();
  for (const cat of OWASP_2021) acc.set(cat.id, { count: 0, rank: -1 });
  for (const f of findings) {
    const id = classifyOwasp(f);
    const cur = acc.get(id) ?? { count: 0, rank: -1 };
    cur.count += 1;
    cur.rank = Math.max(cur.rank, SEV_RANK[f.severity]);
    acc.set(id, cur);
  }
  const rankToSev = (r) => r < 0 ? "none" : ["info", "low", "medium", "high", "critical"][r];
  const rows = OWASP_2021.map((cat) => {
    const a = acc.get(cat.id);
    return { id: cat.id, name: cat.name, count: a.count, maxSeverity: rankToSev(a.rank) };
  });
  for (const id of ["LGPD", "unclassified"]) {
    const a = acc.get(id);
    if (a && a.count > 0) rows.push({ id, name: EXTRA_NAMES[id], count: a.count, maxSeverity: rankToSev(a.rank) });
  }
  return rows;
}
function isAuditReport(r) {
  return Array.isArray(r.checks);
}
var SEVERITY_EMOJI = {
  critical: "\u{1F534}",
  high: "\u{1F7E0}",
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
  info: "\u26AA"
};
var FractaReporter = class {
  outputDir;
  toolVersion;
  constructor(options = {}) {
    this.outputDir = options.outputDir ?? "./fracta-reports";
    this.toolVersion = options.toolVersion ?? "0.0.0";
  }
  async save(report) {
    await mkdir(this.outputDir, { recursive: true });
    const slug2 = report.target.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    const ts = new Date(report.startedAt).toISOString().replace(/[:.]/g, "-").replace("T", "_").substring(0, 19);
    const baseName = `${slug2}-${ts}`;
    const mdPath = join6(this.outputDir, `${baseName}.md`);
    const jsonPath = join6(this.outputDir, `${baseName}.json`);
    const sarifPath = join6(this.outputDir, `${baseName}.sarif`);
    await writeFile(mdPath, this.buildMarkdown(report), "utf-8");
    await writeFile(jsonPath, JSON.stringify(report, null, 2), "utf-8");
    await writeFile(sarifPath, JSON.stringify(toSarif(report, { toolVersion: this.toolVersion }), null, 2), "utf-8");
    return { mdPath, jsonPath, sarifPath };
  }
  buildMarkdown(report) {
    const date = new Date(report.startedAt);
    const dateStr = date.toLocaleDateString("pt-BR") + " " + date.toLocaleTimeString("pt-BR");
    const durationSec = (report.durationMs / 1e3).toFixed(1);
    const inconclusive = isAuditReport(report) && report.verdict === "inconclusive";
    const degradados = isAuditReport(report) ? report.resumo?.checksDegradados ?? [] : [];
    const comRessalvas = report.passed && degradados.length > 0;
    const status = inconclusive ? "\u26A0\uFE0F INCONCLUSIVO" : report.passed ? comRessalvas ? "\u2705 PASSOU \u26A0\uFE0F COM RESSALVAS" : "\u2705 PASSOU" : "\u274C FALHOU";
    const severities = ["critical", "high", "medium", "low", "info"];
    const grouped = /* @__PURE__ */ new Map();
    for (const s of severities) grouped.set(s, []);
    for (const f of report.findings) grouped.get(f.severity).push(f);
    let md = `# \u{1F6E1}\uFE0F Fracta \u2014 Relat\xF3rio de Seguran\xE7a

`;
    md += `| Campo | Valor |
|---|---|
`;
    md += `| Target | ${report.target} |
`;
    md += `| Data | ${dateStr} |
`;
    md += `| Dura\xE7\xE3o | ${durationSec}s |
`;
    md += `| Run ID | \`${report.runId}\` |
`;
    md += `| Status | ${status} |

`;
    if (inconclusive) {
      md += this.buildInconclusiveCallout(report);
    } else if (comRessalvas) {
      md += `> \u2705 **PASSOU \u2014 COM RESSALVAS.** ${degradados.length} verifica\xE7\xE3o(\xF5es) cr\xEDtica(s) N\xC3O rodou(aram): `;
      md += `**${degradados.join(", ")}**.
`;
      md += `> A **aus\xEAncia de achado nesses checks N\xC3O significa "seguro"** \u2014 apenas que n\xE3o foram executados `;
      md += `(ex.: depend\xEAncia faltando, como o gitleaks). Instale/habilite a capacidade e rode de novo.

`;
    }
    md += `## \u{1F4CA} Resumo

`;
    md += `| Severidade | Quantidade |
|---|---|
`;
    md += `| \u{1F534} Critical | ${report.summary.critical} |
`;
    md += `| \u{1F7E0} High | ${report.summary.high} |
`;
    md += `| \u{1F7E1} Medium | ${report.summary.medium} |
`;
    md += `| \u{1F535} Low | ${report.summary.low} |
`;
    md += `| \u26AA Info | ${report.summary.info} |
`;
    md += `| **Total** | **${report.summary.total}** |

`;
    md += this.buildOwaspScorecard(report);
    md += this.buildPriorityBlock(report);
    const severityTitles = {
      critical: "\u{1F534} CR\xCDTICO",
      high: "\u{1F7E0} ALTO",
      medium: "\u{1F7E1} M\xC9DIO",
      low: "\u{1F535} BAIXO",
      info: "\u26AA INFORMATIVO"
    };
    for (const severity of severities) {
      const findings = grouped.get(severity);
      if (findings.length === 0) continue;
      md += `## ${severityTitles[severity]} (${findings.length})

`;
      for (const f of findings) {
        md += `### ${f.title}

`;
        md += `**Agente:** \`${f.agent}\` | **Categoria:** \`${f.category}\`
`;
        if (f.confidence === "low") {
          md += `**Confian\xE7a:** \u{1F535} baixa \u2014 heur\xEDstico ou em arquivo propenso a falso-positivo (teste/fixture/exemplo). Para revis\xE3o; **n\xE3o** derruba o build.
`;
        }
        if (f.endpoint) md += `**Endpoint:** \`${f.endpoint}\`
`;
        md += `
${f.description}

`;
        if (f.evidence) {
          md += `**Evid\xEAncia:**
\`\`\`
${f.evidence}
\`\`\`

`;
        }
        md += `**Corre\xE7\xE3o:** ${f.recommendation}

`;
        md += this.renderProposedFix(f);
        if (f.references && f.references.length > 0) {
          md += `**Refer\xEAncias:** ${f.references.map((r) => `[${r}](${r})`).join(" \xB7 ")}

`;
        }
        md += `---

`;
      }
    }
    if (isAuditReport(report)) {
      md += this.buildTransparencySection(report);
    }
    md += `---

`;
    md += `*Gerado pelo [Fracta](https://fracta.pro?ref=report&utm_source=fracta-report&utm_medium=report&utm_campaign=footer) \u2014 auditoria de seguran\xE7a gr\xE1tis e open-source para SaaS. Monitoramento cont\xEDnuo + regress\xE3o em [fracta.pro](https://fracta.pro?ref=report).*
`;
    md += `*Feito pela PreviusIA, tamb\xE9m criadora do [zap-api.tech](https://zap-api.tech?ref=fracta-report&utm_source=fracta-report&utm_medium=report&utm_campaign=crosssell) \u2014 API de WhatsApp para devs.*
`;
    return md;
  }
  /**
   * Callout de veredito INCONCLUSIVO. A auditoria não conseguiu exercer o alvo
   * (tipicamente staging fora do ar), então a ausência de achados NÃO significa
   * "seguro" — deixa isso explícito no topo, com o motivo concreto.
   */
  /**
   * Scorecard de POSTURA por OWASP Top 10 2021 — sintetiza os achados numa foto de
   * maturidade ("limpo em N, exposto em M"), o que clientes (jurídico/LGPD) leem melhor
   * que uma lista. Classificação por sinal explícito (CWE/OWASP), nunca chute.
   */
  buildOwaspScorecard(report) {
    const rows = buildScorecard(report.findings);
    const owasp = rows.filter((r) => /^A\d\d$/.test(r.id));
    const limpas = owasp.filter((r) => r.count === 0).length;
    const emoji = { critical: "\u{1F534}", high: "\u{1F7E0}", medium: "\u{1F7E1}", low: "\u{1F535}", info: "\u26AA", none: "\u2705" };
    let md = `## \u{1F3AF} Postura por OWASP Top 10 (2021)

`;
    md += `Limpo em **${limpas}/10** categorias. Classifica\xE7\xE3o por sinal expl\xEDcito (CWE/OWASP-API); o que n\xE3o tem sinal confi\xE1vel fica em "N\xE3o classificado" (honestidade > cobertura fake).

`;
    md += `| Categoria | Achados | Pior | Status |
|---|---|---|---|
`;
    for (const r of rows) {
      const status = r.maxSeverity === "none" ? "\u2705 sem achados" : `${emoji[r.maxSeverity]} ${r.maxSeverity}`;
      md += `| ${r.id} \u2014 ${r.name} | ${r.count} | ${r.maxSeverity === "none" ? "\u2014" : r.maxSeverity} | ${status} |
`;
    }
    return md + "\n";
  }
  buildInconclusiveCallout(report) {
    const h = report.targetHealth;
    const comErro = report.resumo?.checksComErro ?? [];
    const motivo = h.stagingResponding === false ? "o alvo (staging) n\xE3o respondeu \u2014 a camada DAST n\xE3o p\xF4de ser exercida." : h.repoAccessible === false ? "o reposit\xF3rio obrigat\xF3rio est\xE1 inacess\xEDvel \u2014 n\xE3o houve o que auditar." : comErro.length > 0 ? `${comErro.length} verifica\xE7\xE3o(\xF5es) falhou(aram) com erro (${comErro.join(", ")}) \u2014 essa(s) dimens\xE3o(\xF5es) N\xC3O foi(ram) medida(s).` : "o alvo n\xE3o p\xF4de ser exercido nesta execu\xE7\xE3o.";
    let md = `> \u26A0\uFE0F **Veredito INCONCLUSIVO:** ${motivo}
`;
    md += `> **Aus\xEAncia de achados aqui N\xC3O significa "seguro"** \u2014 apenas que a auditoria n\xE3o rodou de ponta a ponta.
`;
    md += `> Garanta que o alvo est\xE1 no ar e rode de novo.

`;
    return md;
  }
  /**
   * Bloco de ação prioritária no topo do relatório. Quando a borda LLM produziu
   * uma `prioritization`, respeita exatamente essa ordem ("o que resolver primeiro")
   * e mostra o racional. Sem LLM, cai no determinístico: lista critical + high.
   * Nunca inventa nada — só referencia findings que existem no relatório.
   */
  buildPriorityBlock(report) {
    const byId = new Map(report.findings.map((f) => [f.id, f]));
    const prioritization = isAuditReport(report) ? report.prioritization : void 0;
    if (prioritization && prioritization.order.length > 0) {
      const ordered = prioritization.order.map((id) => byId.get(id)).filter((f) => f !== void 0);
      if (ordered.length > 0) {
        let md2 = `## \u{1F3AF} A\xE7\xE3o Priorit\xE1ria

`;
        md2 += `> Ordem sugerida pela borda LLM (prioriza por contexto do SaaS; **n\xE3o** altera severidade nem o conjunto de achados).

`;
        ordered.forEach((f, i) => {
          md2 += `${i + 1}. ${SEVERITY_EMOJI[f.severity]} **${f.title}** \u2014 \`${f.agent}\`
`;
        });
        if (prioritization.rationale) {
          md2 += `
> ${prioritization.rationale.trim().replace(/\n+/g, "\n> ")}
`;
        }
        md2 += `
`;
        return md2;
      }
    }
    const topo = report.findings.filter(
      (f) => (f.severity === "critical" || f.severity === "high") && f.confidence !== "low"
    );
    if (topo.length === 0) return "";
    let md = `## \u{1F3AF} A\xE7\xE3o Priorit\xE1ria (${topo.length})

`;
    md += `> Achados de severidade **cr\xEDtica/alta** \u2014 tratar primeiro.

`;
    for (const f of topo) {
      md += `- ${SEVERITY_EMOJI[f.severity]} **${f.title}** \u2014 \`${f.agent}\`
`;
    }
    md += `
`;
    return md;
  }
  /**
   * Renderiza a correção PROPOSTA (gated) de um finding, se houver. Mostra
   * descrição, comando e/ou diff e — sempre — o risco de aplicar. Deixa explícito
   * que o Fracta NUNCA aplica a correção sozinho (regra 2/6).
   */
  renderProposedFix(f) {
    const fix = f.proposedFix;
    if (!fix) return "";
    let md = `**\u{1F527} Corre\xE7\xE3o proposta (gated \u2014 n\xE3o aplicada automaticamente):**

`;
    md += `${fix.description}

`;
    if (fix.command) {
      md += `\`\`\`bash
${fix.command}
\`\`\`

`;
    }
    if (fix.diff) {
      md += `\`\`\`diff
${fix.diff}
\`\`\`

`;
    }
    md += `**Risco de aplicar:** ${fix.riskOfApplying}

`;
    return md;
  }
  /**
   * Transparência sobre o que NÃO foi verificado. Parte da robustez:
   * "não verificado" ≠ "seguro". Lista checks com erro e checks pulados.
   */
  buildTransparencySection(report) {
    const { resumo } = report;
    let md = "";
    if (resumo.regressoes > 0) {
      md += `## \u23EA Regress\xF5es (${resumo.regressoes})

`;
      const regs = report.findings.filter((f) => f.status === "regression");
      for (const f of regs) {
        md += `- **${f.title}** (\`${f.agent}\`, ${f.severity}) \u2014 voltou a aparecer.
`;
      }
      md += `
`;
    }
    if (resumo.checksComErro.length > 0 || resumo.checksPulados.length > 0) {
      md += `## \u26A0\uFE0F Checks que N\xC3O rodaram

`;
      md += `> Estes checks n\xE3o produziram veredito. Aus\xEAncia de achado aqui **n\xE3o** significa "seguro".

`;
      const byAgent = new Map(report.checks.map((c) => [c.agent, c]));
      if (resumo.checksComErro.length > 0) {
        md += `**Erro (falha isolada):**

`;
        for (const agent of resumo.checksComErro) {
          md += `- \`${agent}\` \u2014 ${byAgent.get(agent)?.motivo ?? "erro n\xE3o especificado"}
`;
        }
        md += `
`;
      }
      if (resumo.checksPulados.length > 0) {
        md += `**Pulados (sem dados de entrada):**

`;
        for (const agent of resumo.checksPulados) {
          md += `- \`${agent}\` \u2014 ${byAgent.get(agent)?.motivo ?? "sem motivo registrado"}
`;
        }
        md += `
`;
      }
    }
    return md;
  }
};

// ../store/dist/index.js
import { createRequire } from "module";
var nodeRequire = createRequire(import.meta.url);
function loadSqlite() {
  try {
    return nodeRequire("node:sqlite");
  } catch (err) {
    throw new Error(
      `node:sqlite indispon\xEDvel (requer Node >= 22.5; rodando ${process.version}): ${err.message}`
    );
  }
}
var SqliteFindingStore = class {
  db;
  constructor(path = "./fracta-state.db") {
    const { DatabaseSync } = loadSqlite();
    this.db = new DatabaseSync(path);
    if (path !== ":memory:") {
      try {
        this.db.exec("PRAGMA journal_mode = WAL");
      } catch {
      }
    }
    this.migrate();
  }
  migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS finding_history (
        id          TEXT NOT NULL,
        saas        TEXT NOT NULL,
        camada      TEXT NOT NULL,
        severidade  TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        resolved    INTEGER NOT NULL DEFAULT 0,
        suppressed  INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (id, saas)
      );
      CREATE INDEX IF NOT EXISTS idx_fh_saas_camada ON finding_history (saas, camada);

      CREATE TABLE IF NOT EXISTS audit_run (
        id          TEXT PRIMARY KEY,
        saas        TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        report_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ar_saas_ts ON audit_run (saas, timestamp);
    `);
  }
  applyStatus(saas, findings, suppressions = []) {
    const supp = new Set(suppressions);
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const getRow = this.db.prepare("SELECT resolved FROM finding_history WHERE id = ? AND saas = ?");
    const upsert = this.db.prepare(`
      INSERT INTO finding_history (id, saas, camada, severidade, first_seen, last_seen, resolved, suppressed)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?)
      ON CONFLICT(id, saas) DO UPDATE SET
        last_seen = excluded.last_seen,
        resolved = 0,
        severidade = excluded.severidade,
        suppressed = excluded.suppressed
    `);
    const listOpen = this.db.prepare("SELECT id FROM finding_history WHERE saas = ? AND resolved = 0");
    const markResolved = this.db.prepare("UPDATE finding_history SET resolved = 1 WHERE id = ? AND saas = ?");
    const result = [];
    const presentIds = /* @__PURE__ */ new Set();
    this.db.exec("BEGIN");
    try {
      for (const f of findings) {
        presentIds.add(f.id);
        const prev = getRow.get(f.id, saas);
        const isSuppressed = supp.has(f.id);
        let status;
        if (isSuppressed) status = "suppressed";
        else if (prev && prev.resolved === 1) status = "regression";
        else status = "open";
        upsert.run(
          f.id,
          saas,
          f.camada ?? f.category,
          f.severity,
          now,
          now,
          isSuppressed ? 1 : 0
        );
        result.push({ ...f, status });
      }
      const openRows = listOpen.all(saas);
      for (const row of openRows) {
        if (!presentIds.has(row.id)) markResolved.run(row.id, saas);
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
    return result;
  }
  recordRun(report) {
    this.db.prepare("INSERT INTO audit_run (id, saas, timestamp, report_json) VALUES (?, ?, ?, ?)").run(report.runId, report.saas, report.timestamp, JSON.stringify(report));
  }
  close() {
    this.db.close();
  }
};

// ../llm/dist/index.js
var DEFAULT_MODEL = "claude-opus-4-8";
var SYSTEM_PROMPT = `Voc\xEA \xE9 a borda de prioriza\xE7\xE3o do Fracta, um auditor de seguran\xE7a.
Os achados (findings) J\xC1 foram detectados de forma determin\xEDstica por ferramentas. Seu papel \xE9 ESTRITO:
1. PRIORIZAR: ordenar os achados por "o que resolver primeiro neste SaaS hoje", considerando severidade, regress\xE3o e o perfil do produto.
2. REDIGIR corre\xE7\xE3o: para achados sem corre\xE7\xE3o proposta, escrever uma remedia\xE7\xE3o acion\xE1vel.

PROIBI\xC7\xD5ES ABSOLUTAS:
- N\xC3O invente achados nem remova achados. Use apenas os ids fornecidos.
- N\xC3O decida se algo \xE9 vulner\xE1vel (isso \xE9 da ferramenta).
- N\xC3O altere a severidade de nenhum achado.
- N\xC3O aplique nenhuma corre\xE7\xE3o \u2014 apenas descreva.
- "riskOfApplying" \xE9 OBRIGAT\xD3RIO e honesto: o que pode quebrar se a corre\xE7\xE3o for aplicada.

Responda SOMENTE com JSON v\xE1lido, sem texto fora do JSON, neste formato:
{
  "order": ["<id>", "..."],            // ids fornecidos, em ordem de prioridade
  "rationale": "<por que esta ordem>",
  "fixes": [
    { "id": "<id>", "description": "<remedia\xE7\xE3o acion\xE1vel>", "command": "<opcional>", "diff": "<opcional>", "riskOfApplying": "<o que pode quebrar>" }
  ]
}`;
var LlmEnricher = class {
  client;
  model;
  verbose;
  constructor(opts = {}) {
    this.model = opts.model ?? process.env.FRACTA_LLM_MODEL ?? DEFAULT_MODEL;
    this.verbose = opts.verbose ?? false;
    if (opts.client) {
      this.client = opts.client;
    } else {
      const apiKey = opts.apiKey ?? process.env.ANTHROPIC_API_KEY;
      this.client = apiKey ? createAnthropicClient(apiKey) : void 0;
    }
  }
  /** true se há um provedor configurado (API key ou cliente injetado). */
  get enabled() {
    return !!this.client;
  }
  async enrich(report) {
    if (!this.client || report.findings.length === 0) return report;
    const raw = await this.client.complete({
      model: this.model,
      system: SYSTEM_PROMPT,
      user: buildUserPrompt(report),
      maxTokens: 8e3
    });
    const parsed = parseModelJson(raw);
    if (!parsed) {
      if (this.verbose) console.error("[Fracta] LLM: resposta n\xE3o interpret\xE1vel; mantendo relat\xF3rio determin\xEDstico");
      return report;
    }
    return applyEnrichment(report, parsed);
  }
};
function buildUserPrompt(report) {
  const findings = report.findings.map((f) => ({
    id: f.id,
    camada: f.camada ?? f.category,
    severidade: f.severity,
    status: f.status ?? "open",
    titulo: f.title,
    achado: truncate(f.description, 500),
    evidencia: f.evidence ? truncate(f.evidence, 300) : void 0,
    temCorrecao: !!f.proposedFix
  }));
  return `SaaS: ${report.saas}
Regress\xF5es: ${report.resumo.regressoes}

Achados:
${JSON.stringify(findings, null, 2)}`;
}
function applyEnrichment(report, output) {
  const known = new Map(report.findings.map((f) => [f.id, f]));
  const requested = Array.isArray(output.order) ? output.order.filter((x) => typeof x === "string") : [];
  const seen = /* @__PURE__ */ new Set();
  const order = [];
  for (const id of requested) {
    if (known.has(id) && !seen.has(id)) {
      seen.add(id);
      order.push(id);
    }
  }
  for (const f of report.findings) {
    if (!seen.has(f.id)) order.push(f.id);
  }
  const fixesById = /* @__PURE__ */ new Map();
  if (Array.isArray(output.fixes)) {
    for (const raw of output.fixes) {
      if (!raw || typeof raw !== "object") continue;
      const fix = raw;
      const id = typeof fix.id === "string" ? fix.id : void 0;
      const description = typeof fix.description === "string" ? fix.description : void 0;
      const riskOfApplying = typeof fix.riskOfApplying === "string" ? fix.riskOfApplying : void 0;
      if (!id || !description || !riskOfApplying || !known.has(id)) continue;
      const proposed = { description, riskOfApplying };
      if (typeof fix.command === "string") proposed.command = fix.command;
      if (typeof fix.diff === "string") proposed.diff = fix.diff;
      fixesById.set(id, proposed);
    }
  }
  const findings = report.findings.map((f) => {
    if (!f.proposedFix && fixesById.has(f.id)) {
      return { ...f, proposedFix: fixesById.get(f.id) };
    }
    return f;
  });
  const rationale = typeof output.rationale === "string" ? output.rationale : void 0;
  return {
    ...report,
    findings,
    prioritization: { order, rationale }
  };
}
function parseModelJson(raw) {
  if (!raw) return null;
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1] : raw;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    const obj = JSON.parse(candidate.slice(start, end + 1));
    return obj && typeof obj === "object" ? obj : null;
  } catch {
    return null;
  }
}
function truncate(s, max) {
  return s.length > max ? `${s.slice(0, max)}\u2026` : s;
}
function createAnthropicClient(apiKey) {
  return {
    async complete({ model, system, user, maxTokens }) {
      const mod = await import("./sdk-XAPX3I3B.js");
      const Anthropic = mod.default;
      const client = new Anthropic({ apiKey });
      const resp = await client.messages.create({
        model,
        max_tokens: maxTokens,
        system,
        messages: [{ role: "user", content: user }]
      });
      const blocks = resp.content;
      return blocks.filter((b) => b.type === "text").map((b) => b.text ?? "").join("\n");
    }
  };
}

// package.json
var package_default = {
  name: "fractascan",
  version: "0.1.18",
  description: "Fracta \u2014 auditor de seguran\xE7a + LGPD multi-agente e determin\xEDstico para SaaS (DAST + SAST, relat\xF3rio A\u2013F). CLI: fracta scan.",
  license: "MIT",
  author: "Anderson Gadelha",
  homepage: "https://github.com/andersongadelhaadv-cmyk/fracta#readme",
  repository: {
    type: "git",
    url: "https://github.com/andersongadelhaadv-cmyk/fracta.git",
    directory: "packages/cli"
  },
  bugs: {
    url: "https://github.com/andersongadelhaadv-cmyk/fracta/issues"
  },
  keywords: [
    "fracta",
    "cli",
    "security",
    "scanner",
    "lgpd",
    "owasp"
  ],
  type: "module",
  main: "dist/index.js",
  bin: {
    fracta: "./dist/index.js"
  },
  files: [
    "dist",
    "README.md"
  ],
  engines: {
    node: ">=20"
  },
  publishConfig: {
    access: "public"
  },
  scripts: {
    build: "tsup",
    dev: "tsup --watch",
    test: "vitest run --passWithNoTests"
  },
  dependencies: {
    yaml: "^2.4.0"
  },
  devDependencies: {
    "@fracta/agent-auth": "workspace:*",
    "@fracta/agent-compliance": "workspace:*",
    "@fracta/agent-dependencies": "workspace:*",
    "@fracta/agent-dns": "workspace:*",
    "@fracta/agent-docs": "workspace:*",
    "@fracta/agent-headers": "workspace:*",
    "@fracta/agent-idor": "workspace:*",
    "@fracta/agent-infra": "workspace:*",
    "@fracta/agent-semgrep": "workspace:*",
    "@fracta/agent-race": "workspace:*",
    "@fracta/agent-secrets": "workspace:*",
    "@fracta/agent-stack": "workspace:*",
    "@fracta/agent-stripe": "workspace:*",
    "@fracta/agent-tenant": "workspace:*",
    "@fracta/core": "workspace:*",
    "@fracta/llm": "workspace:*",
    "@fracta/reporter": "workspace:*",
    "@fracta/skill-nestjs": "workspace:*",
    "@fracta/skill-prisma": "workspace:*",
    "@fracta/skill-supabase": "workspace:*",
    "@fracta/store": "workspace:*",
    "@fracta/verify": "workspace:*",
    "@types/node": "*",
    tsup: "*",
    typescript: "*"
  }
};

// src/index.ts
var BANNER = `
\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557
\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u255A\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u255D\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557
\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551        \u2588\u2588\u2551   \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551
\u2588\u2588\u2554\u2550\u2550\u255D  \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551        \u2588\u2588\u2551   \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551
\u2588\u2588\u2551     \u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551\u255A\u2588\u2588\u2588\u2588\u2588\u2588\u2557   \u2588\u2588\u2551   \u2588\u2588\u2551  \u2588\u2588\u2551
\u255A\u2550\u255D     \u255A\u2550\u255D  \u255A\u2550\u255D\u255A\u2550\u255D  \u255A\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D   \u255A\u2550\u255D   \u255A\u2550\u255D  \u255A\u2550\u255D

The Complete SaaS Audit Framework \u2014 v${package_default.version}
`;
async function loadTargets(configPath) {
  const raw = await readFile6(configPath, "utf-8");
  const resolved = raw.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] ?? "");
  const parsed = parseYaml(resolved);
  const targets = Object.entries(parsed.targets).map(([name, t]) => ({ name, ...t }));
  for (const t of targets) assertUsableTarget(t);
  return targets;
}
async function main() {
  let values;
  let positionals;
  try {
    ;
    ({ values, positionals } = parseCliArgs(process.argv.slice(2)));
  } catch (err) {
    if (err instanceof CliUsageError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }
  if (values.version) {
    console.log(package_default.version);
    process.exit(0);
  }
  console.log(BANNER);
  const command = positionals[0] ?? "scan";
  const VALID_COMMANDS = ["scan", "docs", "verify", "verify-csp", "init", "help"];
  if (!VALID_COMMANDS.includes(command)) {
    console.error(`[Fracta] Unknown command: "${command}"`);
    console.error(`         Valid commands: ${VALID_COMMANDS.join(", ")}`);
    console.error(`         Run "fracta --help" for usage.`);
    process.exit(1);
  }
  if (values.help || command === "help") {
    console.log(`
Usage: fracta <command> [options]

Commands:
  scan          Run full security scan (default)
  docs          Run documentation audit only
  verify <url>      Verifica\xE7\xE3o em runtime (browser) de consentimento/trackers.
  verify-csp <url>  Prova em runtime (browser) a COBERTURA da CSP: quantos <script>
                    a pol\xEDtica de fato cobre (pega "CSP estrita mas N sem nonce").
  init [path]   Cria um targets.yaml inicial comentado (default: ./configs/targets.yaml).

Options:
  -t, --target      Target name from targets.yaml (default: all)
  -c, --config      Path to targets.yaml (default: ./configs/targets.yaml)
  -d, --depth       Scan depth: quick | full | paranoid (default: full)
  -o, --output      Output directory (default: ./fracta-reports)
  --state           SQLite state file for regression/suppression (default: ./fracta-state.db)
  --no-state        Disable cross-run state (no regression/suppression)
  --llm             OPT-IN: enable the LLM edge (prioritization/fix drafting).
                    CONSOME TOKENS. Default OFF \u2192 zero tokens. Requires ANTHROPIC_API_KEY.
                    Modelo via FRACTA_LLM_MODEL (default claude-opus-4-8; use um mais barato p/ economizar).
  --no-llm          (redundante; LLM j\xE1 \xE9 off por padr\xE3o) for\xE7a o LLM desligado
  --fail-on         Severities that cause exit(1) (default: critical,high)
  --docs-path       Repo path for the dedicated 'docs' command (default: ./).
                    In 'scan', DOCS uses the target's repoPath and skips if absent.
  --force           (init) sobrescreve um targets.yaml existente
  -v, --verbose     Verbose output
  -V, --version     Imprime a vers\xE3o e sai
  -h, --help        Show this help
`);
    process.exit(0);
  }
  if (command === "init") {
    const { runInit } = await import("./init-EUSLT3FC.js");
    const path = positionals[1] ?? values.config;
    const result = await runInit(
      { path, force: values.force },
      {
        exists: async (p) => {
          try {
            await access(p);
            return true;
          } catch {
            return false;
          }
        },
        write: async (p, content) => {
          await mkdir2(dirname(p), { recursive: true });
          await writeFile2(p, content, "utf-8");
        }
      }
    );
    console.log(result.message);
    process.exit(result.ok ? 0 : 1);
  }
  if (command === "verify") {
    const targetUrl = positionals[1];
    if (!targetUrl) {
      console.error("[Fracta] Uso: fractascan verify <url>");
      process.exit(2);
    }
    try {
      const { RuntimeVerifier } = await import("./dist-XCY4P772.js");
      const report = await new RuntimeVerifier().verifyConsent(targetUrl);
      console.log(`Verifica\xE7\xE3o em runtime de ${report.url}`);
      console.log(report.evidence.firedBeforeInteraction ? `\u26A0\uFE0F  trackers dispararam ANTES do consentimento: ${report.evidence.trackers.map((t) => t.name).join(", ")}` : "\u2705 nenhum tracker disparou antes do consentimento");
      console.log(`CMP: ${report.evidence.cmp.detected ? report.evidence.cmp.vendor : "n\xE3o detectado"}`);
      for (const f of report.findings) console.log(`- [${f.severity}] ${f.title}`);
      process.exit(0);
    } catch (e) {
      const err = e;
      console.error(err.name === "BrowserUnavailableError" ? err.message : `[Fracta] Falha na verifica\xE7\xE3o: ${err.message}`);
      process.exit(1);
    }
  }
  if (command === "verify-csp") {
    const targetUrl = positionals[1];
    if (!targetUrl) {
      console.error("[Fracta] Uso: fractascan verify-csp <url>");
      process.exit(2);
    }
    try {
      const { RuntimeCspVerifier } = await import("./dist-XCY4P772.js");
      const { formatCspCli } = await import("./csp-cli-format-WPU5K4QA.js");
      const report = await new RuntimeCspVerifier().verifyCoverage(targetUrl);
      console.log(formatCspCli(report));
      const acionavel = report.findings.some((f) => f.severity !== "info");
      process.exit(acionavel ? 1 : 0);
    } catch (e) {
      const err = e;
      console.error(err.name === "BrowserUnavailableError" ? err.message : `[Fracta] Falha na auditoria de CSP: ${err.message}`);
      process.exit(1);
    }
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
  const VALID_DEPTHS = ["quick", "full", "paranoid"];
  const depthArg = values.depth;
  if (!VALID_DEPTHS.includes(depthArg)) {
    console.error(`[Fracta] Invalid --depth value: "${depthArg}"`);
    console.error(`         Valid values: ${VALID_DEPTHS.join(", ")}`);
    process.exit(1);
  }
  const depth = depthArg;
  const failOn = values["fail-on"].split(",").map((s) => s.trim());
  const docsPath = values["docs-path"];
  const allAgents = command === "docs" ? [new DocsAgent(docsPath)] : [
    new HeadersAgent(),
    new DnsAgent(),
    new AuthAgent(),
    new IdorAgent(),
    // No scan, o DOCS Agent deriva o repo de `target.repoPath` e PULA se ausente
    // — nunca cai no cwd (escanearia o próprio Fracta). O override `--docs-path`
    // vale só para o comando dedicado `fracta docs`.
    new DocsAgent(),
    new TenantAgent(),
    new RaceAgent(),
    new StripeAgent(),
    new DependenciesAgent(),
    new SecretsAgent(),
    new StackAgent(),
    new InfraAgent(),
    new SemgrepAgent(),
    new ComplianceAgent(),
    new NestJSSkill(),
    new PrismaSkill(),
    new SupabaseSkill()
  ];
  let store;
  if (!values["no-state"]) {
    try {
      store = new SqliteFindingStore(values.state);
    } catch (err) {
      console.warn(`[Fracta] Estado entre runs indispon\xEDvel: ${err.message}`);
      console.warn(`[Fracta] Seguindo SEM regress\xE3o/supress\xE3o (detec\xE7\xE3o intacta). Use --no-state para silenciar.`);
    }
  }
  const llmOn = values.llm && !values["no-llm"];
  if (values.llm && !process.env.ANTHROPIC_API_KEY) {
    console.warn("[Fracta] --llm pedido, mas ANTHROPIC_API_KEY ausente \u2014 seguindo SEM LLM (zero tokens).");
  }
  const enricher = llmOn ? new LlmEnricher({ verbose: values.verbose }) : void 0;
  if (enricher) {
    console.log(`[Fracta] LLM enrichment LIGADO \u2014 CONSOME TOKENS (modelo: ${process.env.FRACTA_LLM_MODEL ?? "claude-opus-4-8"}).`);
  }
  const orchestrator = new FractaOrchestrator({
    concurrency: 3,
    failOn,
    depth,
    verbose: values.verbose,
    store,
    enricher
  });
  orchestrator.registerAgents(allAgents);
  const reporter = new FractaReporter({ outputDir: values.output, toolVersion: package_default.version });
  let anyFailed = false;
  try {
    for (const target of targets) {
      const report = await orchestrator.scan(target);
      const { mdPath, jsonPath, sarifPath } = await reporter.save(report);
      console.log(`
[Fracta] Reports saved:`);
      console.log(`  Markdown: ${mdPath}`);
      console.log(`  JSON:     ${jsonPath}`);
      console.log(`  SARIF:    ${sarifPath}  (upload no GitHub Code Scanning)`);
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
