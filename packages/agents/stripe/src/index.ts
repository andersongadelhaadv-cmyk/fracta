import { randomUUID, createHmac } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'

const WEBHOOK_PATHS = [
  '/api/stripe/webhook', '/api/webhooks/stripe', '/api/webhook/stripe',
  '/webhooks/stripe', '/webhook/stripe', '/stripe/webhook',
  '/api/payments/webhook', '/api/billing/webhook',
]

const SAMPLE_EVENT = {
  id: 'evt_fracta_test_00000000',
  object: 'event',
  api_version: '2024-06-20',
  created: Math.floor(Date.now() / 1000),
  type: 'customer.subscription.created',
  data: {
    object: {
      id: 'sub_fracta_test',
      object: 'subscription',
      customer: 'cus_fracta_test',
      status: 'active',
    },
  },
  livemode: false,
  pending_webhooks: 1,
  request: { id: null, idempotency_key: null },
}

function buildSignature(payload: string, timestamp: number, secret: string): string {
  const signed = `${timestamp}.${payload}`
  const v1 = createHmac('sha256', secret).update(signed).digest('hex')
  return `t=${timestamp},v1=${v1}`
}

export interface StripeAgentOptions {
  webhookSecret?: string
}

export class StripeAgent implements SecurityAgent {
  name = 'STRIPE Agent'
  category: AgentCategory = 'security'
  concurrency = 1
  timeoutMs = 60_000

  private readonly webhookSecret?: string

  constructor(options: StripeAgentOptions = {}) {
    this.webhookSecret = options.webhookSecret ?? process.env.STRIPE_WEBHOOK_SECRET
  }

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target } = scope

    if (!target.stack.includes('stripe')) {
      return findings
    }

    const client = new FractaHttpClient(target.url)
    const ignore = target.ignore ?? []
    const discovered = await this.discoverWebhookPaths(client, ignore)

    if (discovered.length === 0) {
      findings.push({
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        severity: 'info',
        title: 'Stripe declarado em stack, mas nenhum endpoint de webhook descoberto',
        description: 'A stack declara "stripe" no targets.yaml mas nenhuma das rotas comuns de webhook respondeu. Confirme se há webhook recebendo eventos Stripe.',
        recommendation: 'Se o endpoint usa um path customizado, declare-o explicitamente para testes futuros. Caso ainda não exista webhook, o módulo de billing fica cego a falhas de pagamento.',
        createdAt: new Date(),
      })
      return findings
    }

    for (const path of discovered) {
      await this.testEndpoint(scope, client, path, findings)
    }

    return findings
  }

  private async discoverWebhookPaths(
    client: FractaHttpClient,
    ignore: string[]
  ): Promise<string[]> {
    const found: string[] = []
    for (const path of WEBHOOK_PATHS) {
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await client.request(path, {
          method: 'POST',
          body: { ping: 'fracta' },
          timeoutMs: 4_000,
        })
        if (res.status !== 404) found.push(path)
      } catch { /* timeout — endpoint inexistente */ }
    }
    return found
  }

  private async testEndpoint(
    scope: ScanScope,
    client: FractaHttpClient,
    path: string,
    findings: Finding[]
  ): Promise<void> {
    const payload = JSON.stringify(SAMPLE_EVENT)

    const noSig = await this.safePost(client, path, payload, {})
    if (noSig && noSig.status >= 200 && noSig.status < 300) {
      findings.push({
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        severity: 'critical',
        title: `Webhook Stripe aceita POST sem assinatura: ${path}`,
        description: `${path} respondeu HTTP ${noSig.status} para um payload de evento Stripe sem o header Stripe-Signature. Atacante consegue forjar eventos (subscription.created, invoice.paid) e ativar assinaturas/créditos sem pagar.`,
        endpoint: path,
        evidence: `POST ${path} (sem Stripe-Signature) → HTTP ${noSig.status}`,
        recommendation: 'Sempre valide a assinatura com stripe.webhooks.constructEvent antes de qualquer lógica de negócio:\n```typescript\nconst event = stripe.webhooks.constructEvent(\n  req.rawBody,\n  req.headers[\'stripe-signature\'],\n  process.env.STRIPE_WEBHOOK_SECRET,\n);\n```',
        references: [
          'https://docs.stripe.com/webhooks#verify-events',
          'https://cwe.mitre.org/data/definitions/345.html',
        ],
        createdAt: new Date(),
      })
    }

    const fakeSig = await this.safePost(client, path, payload, {
      'Stripe-Signature': `t=${Math.floor(Date.now() / 1000)},v1=0000000000000000000000000000000000000000000000000000000000000000`,
    })
    if (fakeSig && fakeSig.status >= 200 && fakeSig.status < 300) {
      findings.push({
        id: randomUUID(),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        severity: 'critical',
        title: `Webhook Stripe aceita assinatura inválida: ${path}`,
        description: `${path} respondeu HTTP ${fakeSig.status} para Stripe-Signature claramente inválido (v1=0...0). A validação está ausente ou quebrada.`,
        endpoint: path,
        evidence: `POST ${path} com Stripe-Signature=t=...,v1=00...00 → HTTP ${fakeSig.status}`,
        recommendation: 'Use o SDK oficial do Stripe (stripe.webhooks.constructEvent) — implementações manuais costumam falhar por usar comparação não constant-time ou pular a checagem do v1.',
        references: [
          'https://docs.stripe.com/webhooks#verify-events',
          'https://cwe.mitre.org/data/definitions/347.html',
        ],
        createdAt: new Date(),
      })
    }

    if (this.webhookSecret) {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 60 * 60 * 24
      const validSigOldTs = buildSignature(payload, oldTimestamp, this.webhookSecret)
      const replay = await this.safePost(client, path, payload, {
        'Stripe-Signature': validSigOldTs,
      })
      if (replay && replay.status >= 200 && replay.status < 300) {
        findings.push({
          id: randomUUID(),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          severity: 'high',
          title: `Webhook Stripe aceita replay com timestamp de 24h atrás: ${path}`,
          description: `${path} aceitou um evento assinado com timestamp de 24h atrás. Sem janela de tolerância, qualquer evento interceptado/registrado pode ser replayed indefinidamente.`,
          endpoint: path,
          evidence: `POST ${path} com t=${oldTimestamp} (24h atrás) → HTTP ${replay.status}`,
          recommendation: 'Configure tolerância no constructEvent (padrão Stripe: 300s):\n```typescript\nstripe.webhooks.constructEvent(rawBody, sig, secret, 300);\n```',
          references: ['https://docs.stripe.com/webhooks#replay-attacks'],
          createdAt: new Date(),
        })
      }
    }
  }

  private async safePost(
    client: FractaHttpClient,
    path: string,
    rawBody: string,
    headers: Record<string, string>
  ): Promise<{ status: number; raw: string } | null> {
    try {
      const res = await client.request(path, {
        method: 'POST',
        body: JSON.parse(rawBody),
        headers,
        timeoutMs: 5_000,
      })
      return { status: res.status, raw: res.raw }
    } catch {
      return null
    }
  }
}
