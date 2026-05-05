import type { HttpResponse, RequestOptions } from './types.js'

export class FractaHttpClient {
  private readonly baseUrl: string
  private readonly baseHeaders: Record<string, string>

  constructor(baseUrl: string, baseHeaders: Record<string, string> = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '')
    this.baseHeaders = {
      'Content-Type': 'application/json',
      'User-Agent': 'Fracta-Security-Scanner/0.1',
      ...baseHeaders,
    }
  }

  async request(path: string, options: RequestOptions = {}): Promise<HttpResponse> {
    const { method = 'GET', headers = {}, body, timeoutMs = 10_000 } = options
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)

    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: { ...this.baseHeaders, ...headers },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      })

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
