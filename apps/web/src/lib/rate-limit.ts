import 'server-only'
import { InMemoryRateLimiter } from '@fracta/web-scan'
import { RATE_LIMIT } from './config'

const g = globalThis as unknown as { __fractaRl?: InMemoryRateLimiter }

/** Rate-limiter singleton (memória, single-instance no v1). */
export const rateLimiter: InMemoryRateLimiter = (g.__fractaRl ??= new InMemoryRateLimiter(RATE_LIMIT))
