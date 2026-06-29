export interface RateLimitResult { allowed: boolean; retryAfterMs: number }

interface Opts { limit: number; windowMs: number; now?: () => number }

/** Janela deslizante simples por chave (IP). Single-instance (v1). Clock injetável p/ teste. */
export class InMemoryRateLimiter {
  private hits = new Map<string, number[]>()
  private readonly now: () => number
  constructor(private readonly opts: Opts) {
    this.now = opts.now ?? (() => Date.now())
  }
  check(key: string): RateLimitResult {
    const t = this.now()
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
