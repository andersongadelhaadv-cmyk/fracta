import { randomUUID } from 'node:crypto'
import type { Finding } from '@fracta/core'
import { classifyTrackers } from './trackers.js'
import { detectCmp, CMP_GLOBALS, CMP_SELECTORS, type CmpProbe } from './cmp.js'
import { buildVerifyFindings } from './findings.js'
import { assertPublicHost, isRequestHostAllowed } from './ssrf.js'
import { BrowserUnavailableError } from './errors.js'

export interface VerifyReport {
  url: string
  verdict: 'ok' | 'inconclusive'
  findings: Finding[]
  evidence: {
    trackers: { name: string; requests: string[] }[]
    cookiesSetBeforeConsent: string[]
    cmp: { detected: boolean; vendor?: string }
    firedBeforeInteraction: boolean
  }
  verifiedAt: string
}

/** Abstração mínima do que a casca precisa do Playwright (facilita o teste). */
export interface BrowserLoader {
  (): Promise<{
    chromium: {
      launch(opts: { headless: boolean; channel?: string }): Promise<BrowserLike>
    }
  }>
}
export interface BrowserLike {
  newContext(): Promise<ContextLike>
  close(): Promise<void>
}
export interface ContextLike {
  newPage(): Promise<PageLike>
  cookies(): Promise<{ name: string }[]>
}
export interface RouteLike {
  request(): { url(): string }
  continue(): Promise<void>
  abort(): Promise<void>
}
export interface PageLike {
  on(event: 'request', cb: (req: { url(): string }) => void): void
  route(pattern: string, handler: (route: RouteLike) => unknown): Promise<void>
  goto(url: string, opts: { waitUntil: 'networkidle'; timeout: number }): Promise<unknown>
  url(): string
  evaluate<T>(fn: string): Promise<T>
}

const defaultLoader: BrowserLoader = async () => {
  // Import dinâmico: o Playwright NUNCA entra no bundle base; ausente → catch no chamador.
  // playwright-core (não o pacote `playwright`) é o que fica declarado como optionalDependency
  // dos pacotes publicados: é leve e não baixa o browser no postinstall.
  return (await import('playwright-core')) as unknown as Awaited<ReturnType<BrowserLoader>>
}

/**
 * Lança o Chromium com fallback honesto: browser baixado pelo Playwright →
 * Chrome/Edge do sistema (channel) → erro acionável. Assim `npx` funciona pra
 * quem tem Chrome, sem exigir download de ~150MB no install.
 */
export async function launchWithFallback(
  chromium: { launch(o: { headless: boolean; channel?: string }): Promise<BrowserLike> },
): Promise<BrowserLike> {
  try {
    return await chromium.launch({ headless: true })
  } catch {
    try {
      return await chromium.launch({ headless: true, channel: 'chrome' })
    } catch {
      throw new BrowserUnavailableError(
        'Nenhum Chromium disponível para a verificação em runtime. Rode `npx playwright install chromium`, ou tenha o Google Chrome instalado.',
      )
    }
  }
}

export class RuntimeVerifier {
  private readonly loadBrowser: BrowserLoader
  private readonly allowPrivate: boolean
  constructor(opts: { loadBrowser?: BrowserLoader; allowPrivateForTest?: boolean } = {}) {
    this.loadBrowser = opts.loadBrowser ?? defaultLoader
    this.allowPrivate = !!opts.allowPrivateForTest
    if (opts.allowPrivateForTest && process.env.NODE_ENV !== 'test') {
      throw new Error('allowPrivateForTest só é permitido em teste (NODE_ENV=test)')
    }
  }

  async verifyConsent(input: string, opts: { timeoutMs?: number } = {}): Promise<VerifyReport> {
    const url = new URL(/^https?:\/\//.test(input) ? input : `https://${input}`)
    const saas = url.hostname
    const runId = randomUUID()
    const timeout = opts.timeoutMs ?? 15000

    const inconclusive = (): VerifyReport => ({
      url: url.toString(),
      verdict: 'inconclusive',
      findings: [],
      evidence: { trackers: [], cookiesSetBeforeConsent: [], cmp: { detected: false }, firedBeforeInteraction: false },
      verifiedAt: new Date().toISOString(),
    })

    await assertPublicHost(saas, { allowPrivate: this.allowPrivate })

    let pw
    try {
      pw = await this.loadBrowser()
    } catch {
      throw new BrowserUnavailableError(
        'Verificação em runtime requer o Playwright. Garanta o pacote (o fractascan instala playwright-core) e um browser (npx playwright install chromium, ou Chrome do sistema).',
      )
    }

    const browser = await launchWithFallback(pw.chromium)
    try {
      const context = await browser.newContext()
      const page = await context.newPage()
      const requestUrls: string[] = []
      page.on('request', (req) => requestUrls.push(req.url()))

      await page.route('**/*', async (route) => {
        const allowed = await isRequestHostAllowed(route.request().url(), { allowPrivate: this.allowPrivate })
        if (allowed) await route.continue()
        else await route.abort()
      })

      try {
        await page.goto(url.toString(), { waitUntil: 'networkidle', timeout })
      } catch {
        // Honestidade: alvo inacessível → inconclusive (NUNCA verde falso), como o PassiveScanner.
        return inconclusive()
      }

      // Guard pós-navegação: se um redirect aterrissou num host privado/interno,
      // NÃO processamos o alvo (honestidade: inconclusive, nunca extrair de host interno).
      // Cobre o vetor principal (metadata da cloud); o interceptor já bloqueia requests diretos.
      if (!(await isRequestHostAllowed(page.url(), { allowPrivate: this.allowPrivate }))) {
        return inconclusive()
      }

      const probe = await page.evaluate<CmpProbe>(
        `(() => {
          const globals = ${JSON.stringify(CMP_GLOBALS.map(g => g.key))}.filter(k => k in window);
          const selectorsMatched = ${JSON.stringify(CMP_SELECTORS.map(s => s.selector))}.filter(s => !!document.querySelector(s));
          return { globals, selectorsMatched };
        })()`,
      )

      const trackers = classifyTrackers(requestUrls)
      const cmp = detectCmp(probe)
      const cookies = await context.cookies()
      const cookiesSetBeforeConsent = cookies.map(c => c.name).filter(n => /^(_ga|_gid|_gcl|_fbp|_fbc|_hj|_clck|_tt_|_uet)/i.test(n))

      const findings = buildVerifyFindings({ saas, runId, trackers, cookiesBeforeConsent: cookiesSetBeforeConsent, cmp })

      return {
        url: url.toString(),
        verdict: 'ok',
        findings,
        evidence: {
          trackers,
          cookiesSetBeforeConsent,
          cmp,
          firedBeforeInteraction: trackers.length > 0,
        },
        verifiedAt: new Date().toISOString(),
      }
    } finally {
      await browser.close()
    }
  }
}
