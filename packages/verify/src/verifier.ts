import { randomUUID } from 'node:crypto'
import type { Finding } from '@fracta/core'
import { classifyTrackers } from './trackers.js'
import { detectCmp, CMP_GLOBALS, CMP_SELECTORS, type CmpProbe } from './cmp.js'
import { buildVerifyFindings } from './findings.js'
import { assertPublicHost } from './ssrf.js'
import { BrowserUnavailableError, NavigationError } from './errors.js'

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
      launch(opts: { headless: boolean }): Promise<BrowserLike>
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
export interface PageLike {
  on(event: 'request', cb: (req: { url(): string }) => void): void
  goto(url: string, opts: { waitUntil: 'networkidle'; timeout: number }): Promise<unknown>
  evaluate<T>(fn: string): Promise<T>
}

const defaultLoader: BrowserLoader = async () => {
  // Import dinâmico: o Playwright NUNCA entra no bundle base; ausente → catch no chamador.
  return (await import('playwright')) as unknown as Awaited<ReturnType<BrowserLoader>>
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

    await assertPublicHost(saas, { allowPrivate: this.allowPrivate })

    let pw
    try {
      pw = await this.loadBrowser()
    } catch {
      throw new BrowserUnavailableError(
        'Verificação em runtime requer Chromium. Rode: npx playwright install chromium',
      )
    }

    const browser = await pw.chromium.launch({ headless: true })
    try {
      const context = await browser.newContext()
      const page = await context.newPage()
      const requestUrls: string[] = []
      page.on('request', (req) => requestUrls.push(req.url()))

      try {
        await page.goto(url.toString(), { waitUntil: 'networkidle', timeout })
      } catch {
        throw new NavigationError(`Não consegui carregar ${url.toString()} (timeout/DNS/target down).`)
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
