export interface RateLimitResult { allowed: boolean; retryAfterMs: number }

interface Opts { limit: number; windowMs: number; now?: () => number }

/** Janela deslizante simples por chave (IP). Single-instance (v1). Clock injetável p/ teste. */
export class InMemoryRateLimiter {
  private hits = new Map<string, number[]>()
  private readonly now: () => number
  private lastSweep: number
  constructor(private readonly opts: Opts) {
    this.now = opts.now ?? (() => Date.now())
    this.lastSweep = this.now()
  }
  /** Remove chaves cujos hits já expiraram — evita crescimento ilimitado (memória) num endpoint público. */
  private sweep(t: number): void {
    if (t - this.lastSweep < this.opts.windowMs) return
    const cutoff = t - this.opts.windowMs
    for (const [k, v] of this.hits) {
      if (v.every((ts) => ts <= cutoff)) this.hits.delete(k)
    }
    this.lastSweep = t
  }
  check(key: string): RateLimitResult {
    const t = this.now()
    this.sweep(t)
    const cutoff = t - this.opts.windowMs
    const arr = (this.hits.get(key) ?? []).filter((ts) => ts > cutoff)
    if (arr.length >= this.opts.limit) {
      const retryAfterMs = arr[0] + this.opts.windowMs - t
      this.hits.set(key, arr)
      return { allowed: false, retryAfterMs: Math.max(0, retryAfterMs) }
    }
    arr.push(t)
    this.hits.set(key, arr)
    return { allowed: true, retryAfterMs: 0 }
  }
}
