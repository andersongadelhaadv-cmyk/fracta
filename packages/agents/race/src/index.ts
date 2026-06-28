import { randomUUID } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory, ScanDepth } from '@fracta/core'
import { FractaHttpClient, stableFindingId } from '@fracta/core'

interface RaceProbe {
  path: string
  body: unknown
  description: string
}

const PROBES: RaceProbe[] = [
  { path: '/api/coupons/redeem', body: { code: 'FRACTA-TEST' }, description: 'resgate de cupom' },
  { path: '/api/cupons/aplicar', body: { codigo: 'FRACTA-TEST' }, description: 'aplicação de cupom' },
  { path: '/api/vouchers/redeem', body: { code: 'FRACTA-TEST' }, description: 'resgate de voucher' },
  { path: '/api/invites/accept', body: { token: 'fracta-test-token' }, description: 'aceite de convite' },
  { path: '/api/votes', body: { optionId: 1 }, description: 'votação' },
  { path: '/api/likes', body: { targetId: 1 }, description: 'like/curtida' },
  { path: '/api/withdrawals', body: { amount: 1 }, description: 'saque' },
  { path: '/api/transfers', body: { amount: 1, to: 'test' }, description: 'transferência' },
]

function concurrentCountFor(depth: ScanDepth): number {
  if (depth === 'paranoid') return 20
  if (depth === 'full') return 10
  return 5
}

function loginPathCandidates(authEndpoint?: string): string[] {
  const defaults = ['/api/auth/login', '/auth/login', '/api/login', '/login']
  if (authEndpoint) return [authEndpoint, ...defaults.filter(p => p !== authEndpoint)]
  return defaults
}

export class RaceAgent implements SecurityAgent {
  name = 'RACE Agent'
  category: AgentCategory = 'security'
  concurrency = 1
  timeoutMs = 120_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target, depth } = scope

    if (depth === 'quick') {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: 'race-skipped:quick' }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'info',
        title: 'RACE Agent — depth=quick pula testes destrutivos',
        description: 'Testes de race condition envolvem rajadas de POSTs concorrentes. Em quick scan eles são pulados para não impactar o staging.',
        recommendation: 'Use --depth full ou --depth paranoid para rodar RACE Agent completo.',
        createdAt: new Date(),
      })
      await this.runTimingProbe(scope, findings)
      return findings
    }

    let client: FractaHttpClient
    if (target.auth?.credentials?.email && target.auth?.credentials?.password && target.auth?.endpoint) {
      try {
        const result = await FractaHttpClient.withJwt(
          target.url,
          target.auth.endpoint,
          { email: target.auth.credentials.email, password: target.auth.credentials.password }
        )
        client = result.client
      } catch {
        client = new FractaHttpClient(target.url)
      }
    } else {
      client = new FractaHttpClient(target.url)
    }

    const ignore = target.ignore ?? []
    const burst = concurrentCountFor(depth)

    for (const probe of PROBES) {
      if (ignore.some(i => probe.path.startsWith(i))) continue
      await this.runBurst(scope, client, probe, burst, findings)
    }

    await this.runTimingProbe(scope, findings)

    return findings
  }

  private async runBurst(
    scope: ScanScope,
    client: FractaHttpClient,
    probe: RaceProbe,
    burst: number,
    findings: Finding[]
  ): Promise<void> {
    const responses = await Promise.allSettled(
      Array.from({ length: burst }, () =>
        client.request(probe.path, { method: 'POST', body: probe.body, timeoutMs: 5_000 })
      )
    )

    let successes = 0
    let notFound = 0
    for (const r of responses) {
      if (r.status === 'fulfilled') {
        if (r.value.status >= 200 && r.value.status < 300) successes++
        else if (r.value.status === 404) notFound++
      }
    }

    if (notFound >= Math.ceil(burst * 0.6)) return

    if (successes >= 2) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `race-condition:${probe.path}`, location: probe.path }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: 'high',
        title: `Race condition em ${probe.path} (${probe.description})`,
        description: `Disparei ${burst} POSTs concorrentes em ${probe.path}; ${successes} responderam 2xx. Ações que devem ser idempotentes (${probe.description}) não devem aceitar múltiplas execuções simultâneas.`,
        endpoint: probe.path,
        evidence: `POST x${burst} concorrentes → ${successes} sucessos / ${notFound} 404 / ${burst - successes - notFound} outros`,
        recommendation: 'Use lock pessimista no banco ou idempotency keys:\n```typescript\nawait this.prisma.$transaction(async (tx) => {\n  const coupon = await tx.coupon.findUnique({\n    where: { code }, select: { id: true, redeemedAt: true },\n  });\n  if (coupon?.redeemedAt) throw new ConflictException();\n  await tx.coupon.update({\n    where: { id: coupon.id, redeemedAt: null },\n    data: { redeemedAt: new Date(), redeemedBy: userId },\n  });\n});\n```',
        references: [
          'https://owasp.org/www-community/vulnerabilities/Race_condition',
          'https://cwe.mitre.org/data/definitions/362.html',
        ],
        createdAt: new Date(),
      })
    }
  }

  private async runTimingProbe(scope: ScanScope, findings: Finding[]): Promise<void> {
    const { target } = scope
    if (!target.auth?.credentials?.email) return

    const paths = loginPathCandidates(target.auth.endpoint)
    const baseClient = new FractaHttpClient(target.url)
    const samples = 5

    for (const path of paths) {
      const validEmail = target.auth.credentials.email
      const fakeEmail = `does-not-exist-${randomUUID().substring(0, 8)}@fracta.test`

      const timesValid = await this.measureLogin(baseClient, path, validEmail, samples)
      const timesFake = await this.measureLogin(baseClient, path, fakeEmail, samples)

      if (timesValid.length < samples || timesFake.length < samples) continue

      const avgValid = avg(timesValid)
      const avgFake = avg(timesFake)
      const delta = Math.abs(avgValid - avgFake)

      if (delta > 100) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `timing-attack:${path}`, location: path }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: 'medium',
          title: `Timing attack possível em ${path}: enumeração de usuários`,
          description: `Login com email existente (${avgValid.toFixed(0)}ms) vs inexistente (${avgFake.toFixed(0)}ms) tem variação de ${delta.toFixed(0)}ms — atacante consegue enumerar usuários medindo o tempo de resposta.`,
          endpoint: path,
          evidence: `Avg válido: ${avgValid.toFixed(0)}ms / Avg inexistente: ${avgFake.toFixed(0)}ms / Δ=${delta.toFixed(0)}ms`,
          recommendation: 'Sempre execute a verificação de senha (bcrypt.compare) mesmo se o usuário não existir — compare contra um hash dummy fixo:\n```typescript\nconst DUMMY_HASH = \'$2b$10$abcdefghijklmnopqrstuv\';\nconst hash = user?.password ?? DUMMY_HASH;\nconst ok = await bcrypt.compare(password, hash);\nif (!user || !ok) throw new UnauthorizedException();\n```',
          references: [
            'https://owasp.org/www-community/attacks/Timing_attack',
            'https://cwe.mitre.org/data/definitions/208.html',
          ],
          createdAt: new Date(),
        })
        break
      }
    }
  }

  private async measureLogin(
    client: FractaHttpClient,
    path: string,
    email: string,
    samples: number
  ): Promise<number[]> {
    const times: number[] = []
    for (let i = 0; i < samples; i++) {
      const start = performance.now()
      try {
        await client.request(path, {
          method: 'POST',
          body: { email, password: 'fracta-wrong-password-9999' },
          timeoutMs: 4_000,
        })
        times.push(performance.now() - start)
      } catch { /* timeout */ }
    }
    return times
  }
}

function avg(nums: number[]): number {
  return nums.reduce((s, n) => s + n, 0) / nums.length
}
