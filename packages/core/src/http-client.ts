import type { HttpResponse, RequestOptions } from './types.js'

/**
 * Opções de transporte do cliente. `dispatcher` é um undici Dispatcher/Agent
 * opcional (tipado como unknown para o core não depender de undici): o
 * `@fracta/web-scan` injeta um agent com `connect.lookup` validador de IP para
 * fechar SSRF por redirect/DNS-rebinding em TODO hop de conexão. `redirect`
 * permite forçar 'manual' onde seguir redirect for perigoso.
 */
export interface HttpClientOptions {
  dispatcher?: unknown
  redirect?: 'follow' | 'manual' | 'error'
}

export class FractaHttpClient {
  private readonly baseUrl: string
  private readonly baseHeaders: Record<string, string>
  private readonly clientOptions: HttpClientOptions

  constructor(baseUrl: string, baseHeaders: Record<string, string> = {}, options: HttpClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '')
    this.baseHeaders = {
      'Content-Type': 'application/json',
      // UA honesto estilo bot (padrão Googlebot): identifica o Fracta + URL, mas
      // sem a palavra "Scanner" que dispara regras ingênuas de WAF. Não resolve
      // fingerprint TLS (JA3) de bot-protection avançada (ex.: Cloudflare em IP de datacenter).
      'User-Agent': 'Mozilla/5.0 (compatible; FractaBot/0.1; +https://fracta.pro)',
      ...baseHeaders,
    }
    this.clientOptions = options
  }

  async request(path: string, options: RequestOptions = {}): Promise<HttpResponse> {
    const { method = 'GET', headers = {}, body, timeoutMs = 10_000, redirect } = options
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)

    try {
      const normalizedPath = path.startsWith('/') ? path : `/${path}`
      // `dispatcher` não está nos tipos lib.dom do fetch, mas o fetch do Node (undici) o aceita.
      const init: Record<string, unknown> = {
        method,
        headers: { ...this.baseHeaders, ...headers },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      }
      const eff = redirect ?? this.clientOptions.redirect
      if (eff) init.redirect = eff
      if (this.clientOptions.dispatcher) init.dispatcher = this.clientOptions.dispatcher
      const res = await fetch(`${this.baseUrl}${normalizedPath}`, init as RequestInit)

      const raw = await res.text()
      let parsed: unknown = raw
      const ct = res.headers.get('content-type') ?? ''
      if (ct.includes('application/json')) {
        try { parsed = JSON.parse(raw) } catch { /* non-json body */ }
      }

      const responseHeaders: Record<string, string> = {}
      res.headers.forEach((value, key) => { responseHeaders[key] = value })

      return { status: res.status, headers: responseHeaders, body: parsed, raw }
    } finally {
      clearTimeout(timer)
    }
  }

  withHeaders(extra: Record<string, string>): FractaHttpClient {
    return new FractaHttpClient(this.baseUrl, { ...this.baseHeaders, ...extra })
  }

  static async withJwt(
    baseUrl: string,
    authEndpoint: string,
    credentials: { email: string; password: string }
  ): Promise<{ client: FractaHttpClient; token: string }> {
    const tmp = new FractaHttpClient(baseUrl)
    const res = await tmp.request(authEndpoint, {
      method: 'POST',
      body: credentials,
    })

    if (res.status >= 400) {
      throw new Error(
        `Auth failed: ${authEndpoint} returned HTTP ${res.status}. Body: ${res.raw.substring(0, 200)}`
      )
    }

    const data = res.body as Record<string, unknown>
    const token =
      (data?.access_token as string) ??
      (data?.token as string) ??
      (data?.accessToken as string) ??
      ((data?.data as Record<string, unknown>)?.token as string)

    if (!token) {
      throw new Error(`Auth failed: no token in response from ${authEndpoint}`)
    }

    const client = new FractaHttpClient(baseUrl, { Authorization: `Bearer ${token}` })
    return { client, token }
  }
}
