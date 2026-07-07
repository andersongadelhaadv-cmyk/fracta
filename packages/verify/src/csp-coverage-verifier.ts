import type { Finding } from '@fracta/core'
import { analyzeCspCoverage, type ScriptTag, type CspViolation } from './csp-coverage.js'
import { assertPublicHost, isRequestHostAllowed } from './ssrf.js'
import { BrowserUnavailableError } from './errors.js'
import { launchWithFallback, defaultLoader, type BrowserLoader } from './verifier.js'

export interface CspCoverageReport {
  url: string
  verdict: 'ok' | 'inconclusive'
  findings: Finding[]
  evidence: {
    cspHeader?: string
    cspReportOnlyHeader?: string
    scriptsTotal: number
    violations: number
  }
  verifiedAt: string
}

/** Casca de browser mínima que capta violação (via init script) + o CSP do doc. */
interface CspPage {
  addInitScript(script: string): Promise<void>
  route(pattern: string, handler: (route: {
    request(): { url(): string }
    continue(): Promise<void>
    abort(): Promise<void>
    fetch(opts?: { maxRedirects?: number }): Promise<{ status(): number; headers(): Record<string, string> }>
    fulfill(opts: { response: { status(): number; headers(): Record<string, string> } }): Promise<void>
  }) => unknown): Promise<void>
  goto(url: string, opts: { waitUntil: 'networkidle'; timeout: number }): Promise<unknown>
  url(): string
  evaluate<T>(fn: string): Promise<T>
}

type HostResolver = (host: string) => Promise<string[]>

// Registrado ANTES de qualquer script da página: acumula os SecurityPolicyViolationEvent
// em window.__fractaCsp para leitura pós-load. É o que dá a prova em runtime (não heurística).
const INIT_SCRIPT = `(() => {
  window.__fractaCsp = [];
  document.addEventListener('securitypolicyviolation', (e) => {
    window.__fractaCsp.push({
      violatedDirective: e.violatedDirective || e.effectiveDirective || '',
      blockedURI: e.blockedURI || 'inline',
      disposition: e.disposition || 'enforce',
    });
  });
})()`

const READ_SCRIPT = `(() => ({
  violations: window.__fractaCsp || [],
  scripts: Array.from(document.querySelectorAll('script')).map((s) => ({
    inline: !s.src,
    src: s.src || undefined,
    hasNonce: !!(s.nonce || s.getAttribute('nonce')),
    hasIntegrity: !!s.getAttribute('integrity'),
  })),
}))()`

/**
 * Auditor de CSP em RUNTIME: carrega a página num browser real, captura as
 * violações que o próprio browser dispara e prova a cobertura de cada <script>
 * — o que um check de header (que só lê a política) jamais pegaria. Reusa a
 * casca SSRF-safe do RuntimeVerifier (validação de host por-hop no redirect).
 */
export class RuntimeCspVerifier {
  private readonly loadBrowser: BrowserLoader
  private readonly allowPrivate: boolean
  private readonly resolver?: HostResolver
  constructor(opts: { loadBrowser?: BrowserLoader; allowPrivateForTest?: boolean; resolver?: HostResolver } = {}) {
    this.loadBrowser = opts.loadBrowser ?? defaultLoader
    this.allowPrivate = !!opts.allowPrivateForTest
    this.resolver = opts.resolver
    if (opts.allowPrivateForTest && process.env.NODE_ENV !== 'test') {
      throw new Error('allowPrivateForTest só é permitido em teste (NODE_ENV=test)')
    }
  }

  async verifyCoverage(input: string, opts: { timeoutMs?: number } = {}): Promise<CspCoverageReport> {
    const url = new URL(/^https?:\/\//.test(input) ? input : `https://${input}`)
    const saas = url.hostname
    const timeout = opts.timeoutMs ?? 15000

    const inconclusive = (): CspCoverageReport => ({
      url: url.toString(),
      verdict: 'inconclusive',
      findings: [],
      evidence: { scriptsTotal: 0, violations: 0 },
      verifiedAt: new Date().toISOString(),
    })

    await assertPublicHost(saas, { allowPrivate: this.allowPrivate, resolver: this.resolver })

    let pw
    try {
      pw = await this.loadBrowser()
    } catch {
      throw new BrowserUnavailableError(
        'Auditoria de CSP em runtime precisa do Playwright (opt-in). Instale junto do Fracta: `npm i -g fractascan playwright-core` (usa o Chrome do sistema; ou `npx playwright install chromium`).',
      )
    }

    const browser = await launchWithFallback(pw.chromium)
    try {
      const context = await browser.newContext()
      const page = (await context.newPage()) as unknown as CspPage
      await page.addInitScript(INIT_SCRIPT)

      let cspHeader: string | undefined
      let cspReportOnlyHeader: string | undefined
      const targetUrl = url.toString()

      const hostAllowed = (u: string) =>
        isRequestHostAllowed(u, { allowPrivate: this.allowPrivate, resolver: this.resolver })

      await page.route('**/*', async (route) => {
        const reqUrl = route.request().url()
        if (!(await hostAllowed(reqUrl))) return void (await route.abort())
        let resp
        try {
          resp = await route.fetch({ maxRedirects: 0 })
        } catch {
          return void (await route.abort())
        }
        const status = resp.status()
        if (status >= 300 && status < 400) {
          const location = resp.headers()['location']
          if (location) {
            let nextUrl: string
            try { nextUrl = new URL(location, reqUrl).toString() } catch { return void (await route.abort()) }
            if (!(await hostAllowed(nextUrl))) return void (await route.abort())
          }
        }
        // Capta a CSP do documento principal (é onde as violações de <script> importam).
        if (reqUrl === targetUrl && status < 300) {
          const h = resp.headers()
          cspHeader = h['content-security-policy'] ?? cspHeader
          cspReportOnlyHeader = h['content-security-policy-report-only'] ?? cspReportOnlyHeader
        }
        await route.fulfill({ response: resp })
      })

      try {
        await page.goto(targetUrl, { waitUntil: 'networkidle', timeout })
      } catch {
        return inconclusive()
      }
      if (!(await hostAllowed(page.url()))) return inconclusive()

      const observed = await page.evaluate<{ violations: CspViolation[]; scripts: ScriptTag[] }>(READ_SCRIPT)

      const findings = analyzeCspCoverage({
        saas,
        runId: url.toString(),
        cspHeader,
        cspReportOnlyHeader,
        scripts: observed.scripts,
        violations: observed.violations,
      })

      return {
        url: targetUrl,
        verdict: 'ok',
        findings,
        evidence: {
          cspHeader,
          cspReportOnlyHeader,
          scriptsTotal: observed.scripts.length,
          violations: observed.violations.length,
        },
        verifiedAt: new Date().toISOString(),
      }
    } finally {
      await browser.close()
    }
  }
}
