import { randomUUID } from 'node:crypto'
import type { Finding, ScanScope } from '@fracta/core'
import { HeadersAgent } from '@fracta/agent-headers'
import { DnsAgent } from '@fracta/agent-dns'
import { validateScanUrl } from './ssrf-guard.js'
import { createSafeClient } from './safe-fetch.js'
import { findCookieIssues } from './cookie-check.js'
import { checkLgpdLite, findPrivacyHref } from './lgpd-lite.js'
import { detectBotChallenge } from './bot-challenge.js'
import { detectStack } from './detect-stack.js'
import { grade } from './grader.js'
import type { PassiveScanResult, ScanCheck, ScanGrade, ScanVerdict } from './types.js'

/** HTML → texto legível (tira script/style/tags) p/ a análise determinística da política. */
function stripHtml(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * Orquestra SÓ checks passivos (apenas GETs, zero intrusão) reusando o motor Fracta:
 * o HEADERS agent existente + cookie flags + LGPD-lite. Todo fetch passa por um
 * cliente endurecido cujo dispatcher valida o IP em CADA conexão (fecha SSRF por
 * redirect e DNS rebinding). Honestidade: só emite nota se o check primário rodou;
 * alvo inacessível → veredito `inconclusive` com nota `null` (NUNCA 'F' nem verde falso).
 */
export class PassiveScanner {
  constructor(private readonly opts: { allowPrivateForTest?: boolean } = {}) {
    // Blindagem: o bypass de SSRF para fixtures locais NUNCA pode ser ligado fora de teste.
    if (opts.allowPrivateForTest && process.env.NODE_ENV !== 'test') {
      throw new Error('allowPrivateForTest só é permitido em ambiente de teste (NODE_ENV=test)')
    }
  }

  async scan(input: string): Promise<PassiveScanResult> {
    const allowPrivate = !!this.opts.allowPrivateForTest
    // Produção SEMPRE valida SSRF antes de tocar a rede. allowPrivate só p/ fixture local.
    const url = allowPrivate
      ? new URL(/^https?:\/\//.test(input) ? input : `https://${input}`)
      : await validateScanUrl(input)
    const saas = url.hostname
    const runId = randomUUID()
    const createClient = createSafeClient(allowPrivate)

    const findings: Finding[] = []
    let headersRan = false
    let contentRan = false
    let detectedStack: string[] = []

    // 1) Conteúdo cru (1 GET passivo): cookies + LGPD-lite + DETECÇÃO DE STACK.
    //    Roda ANTES do HEADERS agent para alimentar o stack detectado → o agente
    //    entrega o fix EXATO (ex.: snippet de next.config.js em vez do genérico).
    try {
      const client = createClient(url.toString())
      const res = await client.request('/', { timeoutMs: 8000 })
      contentRan = true
      const html = res.raw ?? ''
      detectedStack = detectStack(res.headers as Record<string, string | string[] | undefined>, html)
      const sc = res.headers['set-cookie'] as unknown as string[] | string | undefined
      const setCookie = Array.isArray(sc) ? sc : sc ? [sc] : []

      // Se o alvo respondeu com desafio de bot-management, a "página" é o desafio —
      // não inferimos nada dela. Nota honesta e paramos os checks de conteúdo.
      const challenge = detectBotChallenge(res.status, res.headers, html)
      if (challenge.challenged && challenge.vendor) {
        findings.push(...checkLgpdLite(html, setCookie, saas, runId, undefined, { vendor: challenge.vendor }))
      } else {
        findings.push(...findCookieIssues(setCookie, saas, runId))

        // Lê a Política de Privacidade (MESMO host) p/ análise determinística do Art. 9º.
        // +1 GET passivo. Externa/ilegível/desafiada → segue sem ela (honesto).
        let policy: { text: string; url: string } | undefined
        const href = findPrivacyHref(html)
        if (href) {
          try {
            const policyUrl = new URL(href, url)
            if (policyUrl.host === url.host && /^https?:$/.test(policyUrl.protocol)) {
              const pres = await client.request(policyUrl.pathname + policyUrl.search, { timeoutMs: 8000 })
              if (pres.raw && !detectBotChallenge(pres.status, pres.headers, pres.raw).challenged) {
                policy = { text: stripHtml(pres.raw), url: policyUrl.toString() }
              }
            }
          } catch { /* política ilegível/externa — segue sem ela */ }
        }

        findings.push(...checkLgpdLite(html, setCookie, saas, runId, policy))
      }
    } catch { /* idem */ }

    // 2) HEADERS agent (passivo) — reusa o motor, transporte endurecido injetado.
    //    Recebe o stack detectado no passo 1 → recomendações com o fix EXATO do stack.
    try {
      const scope: ScanScope = {
        target: { name: saas, url: url.toString(), stack: detectedStack },
        depth: 'quick',
        agents: ['HEADERS Agent'],
        runId,
        startedAt: new Date(),
      }
      findings.push(...(await new HeadersAgent({ createClient }).run(scope)))
      headersRan = true
    } catch { /* inacessível ou skip — tratado pelo verdict honesto */ }

    // 3) Postura de e-mail/DNS (SPF/DMARC/DKIM) — passivo (só queries DNS), anti-spoofing.
    let dnsRan = false
    try {
      const scope: ScanScope = {
        target: { name: saas, url: url.toString(), stack: [] },
        depth: 'quick',
        agents: ['DNS Agent'],
        runId,
        startedAt: new Date(),
      }
      findings.push(...(await new DnsAgent().run(scope)))
      dnsRan = true
    } catch { /* DNS indisponível — segue sem, honesto */ }

    const checks: ScanCheck[] = [
      { name: 'security-headers', status: headersRan ? 'ok' : 'skipped' },
      { name: 'cookies+lgpd', status: contentRan ? 'ok' : 'skipped' },
      { name: 'email-dns', status: dnsRan ? 'ok' : 'skipped' },
    ]

    // Honestidade (H2/H3): a nota só sai se o check PRIMÁRIO (headers) rodou — senão
    // estaríamos gradando sobre um subconjunto e chamando ausência de "seguro". Alvo
    // não avaliável → inconclusive + nota null (jamais 'F', que leria como "inseguro").
    const graded = headersRan
    const verdict: ScanVerdict = graded ? 'ok' : 'inconclusive'
    const g: { grade: ScanGrade | null; score: number | null } = graded
      ? grade(findings)
      : { grade: null, score: null }

    return {
      url: url.toString(),
      findings,
      grade: g.grade,
      score: g.score,
      verdict,
      checks,
      scannedAt: new Date().toISOString(),
    }
  }
}
