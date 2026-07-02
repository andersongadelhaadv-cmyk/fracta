// src/index.ts
import { createHmac } from "crypto";
import { FractaHttpClient, stableFindingId } from "@fracta/core";
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
export {
  StripeAgent
};
