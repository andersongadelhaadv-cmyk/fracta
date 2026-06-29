# Fracta.pro Scan Engine (`@fracta/web-scan`) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `@fracta/web-scan`, a pure-TS package that runs SSRF-safe **passive** security scans (headers/TLS/cookies/LGPD-lite), grades them A–F, persists shareable results, and rate-limits by IP — the engine the `fracta.pro` web scanner (Plan 2) consumes.

**Architecture:** A new monorepo package `packages/web-scan` that depends on `@fracta/core` (Finding/Severity types, FractaHttpClient) and `@fracta/agent-headers` (reuses the existing passive HEADERS agent). Each unit is a focused file with an injectable dependency (resolver/clock/http/id) so it is unit-testable without real network or randomness. Persistence uses `node:sqlite` (same pattern as `@fracta/store`).

**Tech Stack:** TypeScript, tsup (ESM build), vitest, `node:sqlite` (Node ≥22.5), `node:dns`, `node:crypto`. Matches the existing monorepo (pnpm + turbo).

---

## File Structure

```
packages/web-scan/
  package.json                      # @fracta/web-scan, type:module, tsup esm + dts, vitest
  tsconfig.json                     # extends root, like other packages
  src/
    types.ts                        # ScanGrade, PassiveScanResult, SsrfError
    ssrf-guard.ts                   # isBlockedIp(), validateScanUrl()
    cookie-check.ts                 # findCookieIssues(setCookieHeaders) -> Finding[]
    tls-check.ts                    # checkTls(url, httpGet) -> Finding[]
    lgpd-lite.ts                    # checkLgpdLite(url, html) -> Finding[]
    grader.ts                       # grade(findings) -> { grade, score }
    rate-limiter.ts                 # InMemoryRateLimiter (injectable clock)
    scan-store.ts                   # SqliteScanStore (node:sqlite, :memory: for tests)
    passive-scanner.ts              # PassiveScanner.scan(url) -> PassiveScanResult
    index.ts                        # public exports
  src/__tests__/
    ssrf-guard.test.ts
    cookie-check.test.ts
    lgpd-lite.test.ts
    grader.test.ts
    rate-limiter.test.ts
    scan-store.test.ts
    passive-scanner.test.ts         # integration vs local http fixture
```

Conventions to copy from an existing package (read `packages/agents/headers/package.json` and `packages/store/src/index.ts` first):
- `package.json`: `"type":"module"`, `"build":"tsup src/index.ts --format esm --dts"`, `"test":"vitest run --passWithNoTests"`, deps `@fracta/core`, `@fracta/agent-headers` as `workspace:*`.
- `node:sqlite` loaded via `createRequire(import.meta.url)('node:sqlite')` inside the constructor (NOT a static import — vite/vitest can't resolve it). Copy the `loadSqlite()` pattern from `packages/store/src/index.ts`.

---

## Task 1: Scaffold the package

**Files:**
- Create: `packages/web-scan/package.json`
- Create: `packages/web-scan/tsconfig.json`
- Create: `packages/web-scan/src/index.ts` (temporary empty export)

- [ ] **Step 1: Read an existing package for the exact shape**

Run: read `packages/agents/headers/package.json` and `packages/agents/headers/tsconfig.json`. Mirror them.

- [ ] **Step 2: Write `packages/web-scan/package.json`**

```json
{
  "name": "@fracta/web-scan",
  "version": "0.1.0",
  "description": "SSRF-safe passive scan engine for fracta.pro",
  "license": "MIT",
  "type": "module",
  "main": "dist/index.js",
  "exports": { ".": { "import": "./dist/index.js" } },
  "scripts": {
    "build": "tsup src/index.ts --format esm --dts",
    "test": "vitest run --passWithNoTests"
  },
  "dependencies": {
    "@fracta/core": "workspace:*",
    "@fracta/agent-headers": "workspace:*"
  },
  "devDependencies": { "tsup": "*", "typescript": "*", "@types/node": "*", "vitest": "*" }
}
```

- [ ] **Step 3: Write `packages/web-scan/tsconfig.json`** — copy `packages/agents/headers/tsconfig.json` verbatim (same extends/paths).

- [ ] **Step 4: Write `packages/web-scan/src/index.ts`** (placeholder so build passes)

```ts
export {}
```

- [ ] **Step 5: Install + build**

Run: `pnpm install` then `pnpm --filter @fracta/web-scan build`
Expected: build success, `dist/index.js` created.

- [ ] **Step 6: Commit**

```bash
git add packages/web-scan/package.json packages/web-scan/tsconfig.json packages/web-scan/src/index.ts pnpm-lock.yaml
git commit -m "chore(web-scan): scaffold @fracta/web-scan package"
```

---

## Task 2: Types

**Files:**
- Create: `packages/web-scan/src/types.ts`

- [ ] **Step 1: Write `types.ts`**

```ts
import type { Finding } from '@fracta/core'

export type ScanGrade = 'A' | 'B' | 'C' | 'D' | 'E' | 'F'

/** Veredito honesto: 'ok' = alvo exercido; 'inconclusive' = inacessível (ausência ≠ seguro). */
export type ScanVerdict = 'ok' | 'inconclusive'

export interface PassiveScanResult {
  url: string
  findings: Finding[]
  grade: ScanGrade
  score: number // 0–100
  verdict: ScanVerdict
  scannedAt: string // ISO
}

/** Erro tipado de validação SSRF — a URL foi recusada antes de qualquer fetch. */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SsrfError'
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add packages/web-scan/src/types.ts
git commit -m "feat(web-scan): result + grade + SsrfError types"
```

---

## Task 3: SSRF Guard — `isBlockedIp` (the critical security unit)

**Files:**
- Create: `packages/web-scan/src/ssrf-guard.ts`
- Test: `packages/web-scan/src/__tests__/ssrf-guard.test.ts`

- [ ] **Step 1: Write the failing test for `isBlockedIp`**

```ts
import { describe, it, expect } from 'vitest'
import { isBlockedIp } from '../ssrf-guard'

describe('isBlockedIp', () => {
  it('blocks IPv4 loopback/private/link-local/metadata/unspecified', () => {
    for (const ip of ['127.0.0.1', '127.5.5.5', '10.0.0.1', '172.16.0.1', '172.31.255.255',
      '192.168.1.1', '169.254.169.254', '0.0.0.0']) {
      expect(isBlockedIp(ip), ip).toBe(true)
    }
  })
  it('allows normal public IPv4', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '76.13.170.79']) {
      expect(isBlockedIp(ip), ip).toBe(false)
    }
  })
  it('does NOT treat 172.32.x / 11.x as private (boundary)', () => {
    expect(isBlockedIp('172.32.0.1')).toBe(false)
    expect(isBlockedIp('11.0.0.1')).toBe(false)
  })
  it('blocks IPv6 loopback/link-local/ula', () => {
    for (const ip of ['::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::']) {
      expect(isBlockedIp(ip), ip).toBe(true)
    }
  })
  it('allows public IPv6', () => {
    expect(isBlockedIp('2606:4700:4700::1111')).toBe(false)
  })
})
```

- [ ] **Step 2: Run it — expect FAIL**

Run: `pnpm --filter @fracta/web-scan exec vitest run src/__tests__/ssrf-guard.test.ts`
Expected: FAIL ("isBlockedIp is not a function").

- [ ] **Step 3: Implement `isBlockedIp` in `ssrf-guard.ts`**

```ts
import { SsrfError } from './types'

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const o = Number(p)
    if (o > 255) return null
    n = (n << 8) | o
  }
  return n >>> 0
}

function inV4(ip: number, cidr: string): boolean {
  const [base, bitsStr] = cidr.split('/')
  const bits = Number(bitsStr)
  const baseInt = ipv4ToInt(base)!
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (ip & mask) === (baseInt & mask)
}

const V4_BLOCKED = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
]

/** true = IP que NUNCA deve ser escaneado (interno/privado/reservado). Cobre v4 + v6 comuns. */
export function isBlockedIp(ip: string): boolean {
  const v4 = ipv4ToInt(ip)
  if (v4 !== null) return V4_BLOCKED.some((c) => inV4(v4, c))

  // IPv6 (normaliza minúsculas; trata mapeados ::ffff:1.2.3.4)
  const lower = ip.toLowerCase()
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
  if (mapped) return isBlockedIp(mapped[1])
  if (lower === '::' || lower === '::1') return true
  if (lower.startsWith('fe80:')) return true // link-local
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true // fc00::/7 ULA
  return false
}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `pnpm --filter @fracta/web-scan exec vitest run src/__tests__/ssrf-guard.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/web-scan/src/ssrf-guard.ts packages/web-scan/src/__tests__/ssrf-guard.test.ts
git commit -m "feat(web-scan): isBlockedIp — block internal/private/reserved IPs"
```

---

## Task 4: SSRF Guard — `validateScanUrl` (scheme + DNS resolution)

**Files:**
- Modify: `packages/web-scan/src/ssrf-guard.ts`
- Test: `packages/web-scan/src/__tests__/ssrf-guard.test.ts` (append)

- [ ] **Step 1: Append failing tests**

```ts
import { validateScanUrl } from '../ssrf-guard'
import { SsrfError } from '../types'

describe('validateScanUrl', () => {
  // resolver fake: mapeia host -> IPs (sem DNS real)
  const resolve = (host: string) => Promise.resolve(
    host === 'evil.internal' ? ['10.0.0.5'] :
    host === 'good.example' ? ['93.184.216.34'] : []
  )
  it('rejects non-http(s) schemes', async () => {
    await expect(validateScanUrl('ftp://good.example', { resolve })).rejects.toThrow(SsrfError)
    await expect(validateScanUrl('file:///etc/passwd', { resolve })).rejects.toThrow(SsrfError)
  })
  it('rejects a host that resolves to a private IP', async () => {
    await expect(validateScanUrl('http://evil.internal', { resolve })).rejects.toThrow(SsrfError)
  })
  it('rejects a literal private IP host', async () => {
    await expect(validateScanUrl('http://169.254.169.254/latest/meta-data', { resolve })).rejects.toThrow(SsrfError)
  })
  it('rejects a host with no resolvable address', async () => {
    await expect(validateScanUrl('http://nxdomain.test', { resolve })).rejects.toThrow(SsrfError)
  })
  it('accepts a public https URL and returns a normalized URL', async () => {
    const u = await validateScanUrl('good.example/path', { resolve })
    expect(u.protocol).toBe('https:')
    expect(u.hostname).toBe('good.example')
  })
})
```

- [ ] **Step 2: Run — expect FAIL** (`validateScanUrl is not a function`)

Run: `pnpm --filter @fracta/web-scan exec vitest run src/__tests__/ssrf-guard.test.ts`

- [ ] **Step 3: Implement `validateScanUrl` (append to `ssrf-guard.ts`)**

```ts
import { lookup } from 'node:dns/promises'

export type AddressResolver = (host: string) => Promise<string[]>

const defaultResolver: AddressResolver = async (host) => {
  const records = await lookup(host, { all: true })
  return records.map((r) => r.address)
}

/**
 * Valida uma URL de scan ANTES de qualquer fetch. Sem esquema → assume https.
 * Recusa: esquema != http/https; host que resolve (ou é literal) p/ IP interno;
 * host sem endereço resolvível. Lança SsrfError. Resolver injetável p/ teste.
 */
export async function validateScanUrl(
  input: string,
  opts: { resolve?: AddressResolver } = {},
): Promise<URL> {
  const resolve = opts.resolve ?? defaultResolver
  const raw = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`

  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new SsrfError(`URL inválida: ${input}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfError(`Esquema não permitido: ${url.protocol} (use http/https)`)
  }

  // host literal já bloqueado?
  if (isBlockedIp(url.hostname)) {
    throw new SsrfError('Endereço interno/privado não é escaneável')
  }

  let addrs: string[]
  try {
    addrs = await resolve(url.hostname)
  } catch {
    throw new SsrfError(`Não foi possível resolver o host: ${url.hostname}`)
  }
  if (addrs.length === 0) {
    throw new SsrfError(`Host sem endereço resolvível: ${url.hostname}`)
  }
  if (addrs.some(isBlockedIp)) {
    throw new SsrfError('O host resolve para um endereço interno/privado — recusado')
  }
  return url
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `pnpm --filter @fracta/web-scan exec vitest run src/__tests__/ssrf-guard.test.ts`

- [ ] **Step 5: Commit**

```bash
git add packages/web-scan/src/ssrf-guard.ts packages/web-scan/src/__tests__/ssrf-guard.test.ts
git commit -m "feat(web-scan): validateScanUrl — scheme + DNS SSRF guard"
```

---

## Task 5: Cookie check

**Files:**
- Create: `packages/web-scan/src/cookie-check.ts`
- Test: `packages/web-scan/src/__tests__/cookie-check.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest'
import { findCookieIssues } from '../cookie-check'

describe('findCookieIssues', () => {
  it('flags a cookie missing Secure/HttpOnly/SameSite', () => {
    const f = findCookieIssues(['sid=abc'], 'demo', 'run1')
    expect(f).toHaveLength(1)
    expect(f[0].severity).toBe('low')
    expect(f[0].title).toContain('sid')
  })
  it('passes a fully-flagged cookie', () => {
    expect(findCookieIssues(['sid=abc; Secure; HttpOnly; SameSite=Lax'], 'demo', 'run1')).toHaveLength(0)
  })
  it('returns [] when there are no cookies', () => {
    expect(findCookieIssues([], 'demo', 'run1')).toEqual([])
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

Run: `pnpm --filter @fracta/web-scan exec vitest run src/__tests__/cookie-check.test.ts`

- [ ] **Step 3: Implement `cookie-check.ts`**

```ts
import type { Finding } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

/** Analisa headers Set-Cookie (passivo). Cookie sem Secure/HttpOnly/SameSite → finding low. */
export function findCookieIssues(setCookies: string[], saas: string, runId: string): Finding[] {
  const out: Finding[] = []
  for (const raw of setCookies) {
    const name = raw.split('=')[0]?.trim() ?? '(sem nome)'
    const lower = raw.toLowerCase()
    const missing: string[] = []
    if (!lower.includes('secure')) missing.push('Secure')
    if (!lower.includes('httponly')) missing.push('HttpOnly')
    if (!lower.includes('samesite')) missing.push('SameSite')
    if (missing.length === 0) continue
    out.push({
      id: stableFindingId({ saas, camada: 'security', rule: `cookie-flags:${name}`, location: name }),
      runId, agent: 'COOKIE Check', category: 'security', camada: 'security', severity: 'low',
      title: `Cookie sem flags de segurança: ${name}`,
      description: `O cookie "${name}" não define: ${missing.join(', ')}. Sem essas flags ele é mais exposto a roubo (XSS) e envio cross-site (CSRF).`,
      evidence: `Set-Cookie: ${name}=… (faltam: ${missing.join(', ')})`,
      recommendation: 'Defina Secure, HttpOnly e SameSite (Lax/Strict) nos cookies de sessão.',
      createdAt: new Date(),
    })
  }
  return out
}
```

- [ ] **Step 4: Run — expect PASS**; **Step 5: Commit**

```bash
git add packages/web-scan/src/cookie-check.ts packages/web-scan/src/__tests__/cookie-check.test.ts
git commit -m "feat(web-scan): passive cookie flag check"
```

---

## Task 6: LGPD-lite heuristic (beta)

**Files:**
- Create: `packages/web-scan/src/lgpd-lite.ts`
- Test: `packages/web-scan/src/__tests__/lgpd-lite.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest'
import { checkLgpdLite } from '../lgpd-lite'

describe('checkLgpdLite', () => {
  it('flags missing privacy-policy link', () => {
    const f = checkLgpdLite('<html><body>oi</body></html>', 'demo', 'run1')
    expect(f.some((x) => x.title.toLowerCase().includes('privacidade'))).toBe(true)
  })
  it('passes when a privacy link is present', () => {
    const html = '<a href="/politica-de-privacidade">Privacidade</a>'
    expect(checkLgpdLite(html, 'demo', 'run1').some((x) => x.title.toLowerCase().includes('privacidade'))).toBe(false)
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `lgpd-lite.ts`**

```ts
import type { Finding } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

const PRIVACY_HINT = /privacidade|privacy|pol[ií]tica de privacidade/i

/** Heurística LGPD-lite (BETA, best-effort): só sinaliza ausência de link de política de privacidade. */
export function checkLgpdLite(html: string, saas: string, runId: string): Finding[] {
  if (PRIVACY_HINT.test(html)) return []
  return [{
    id: stableFindingId({ saas, camada: 'compliance', rule: 'lgpd-no-privacy-link' }),
    runId, agent: 'LGPD-lite (beta)', category: 'compliance', camada: 'compliance', severity: 'low',
    title: 'Sem link visível de Política de Privacidade (LGPD-lite, beta)',
    description: 'Heurística beta: não encontrei menção a "política de privacidade" na home. A LGPD exige transparência sobre tratamento de dados. Pode ser falso-positivo (link em outra página).',
    recommendation: 'Publique e linke uma Política de Privacidade clara, com base legal e contato do encarregado (DPO).',
    createdAt: new Date(),
  }]
}
```

- [ ] **Step 4: Run — expect PASS**; **Step 5: Commit**

```bash
git add packages/web-scan/src/lgpd-lite.ts packages/web-scan/src/__tests__/lgpd-lite.test.ts
git commit -m "feat(web-scan): LGPD-lite beta heuristic (privacy link)"
```

---

## Task 7: Grader

**Files:**
- Create: `packages/web-scan/src/grader.ts`
- Test: `packages/web-scan/src/__tests__/grader.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest'
import { grade } from '../grader'
import type { Finding } from '@fracta/core'

const f = (severity: Finding['severity']): Finding => ({
  id: severity, runId: 'r', agent: 'a', category: 'security', camada: 'security',
  severity, title: 't', description: 'd', createdAt: new Date(),
})

describe('grade', () => {
  it('A + 100 when there are no findings', () => {
    expect(grade([])).toEqual({ grade: 'A', score: 100 })
  })
  it('subtracts by severity and never goes below 0', () => {
    const r = grade([f('critical'), f('critical'), f('critical'), f('critical')])
    expect(r.score).toBe(0)
    expect(r.grade).toBe('F')
  })
  it('a single low stays high', () => {
    const r = grade([f('low')])
    expect(r.score).toBe(97)
    expect(r.grade).toBe('A')
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `grader.ts`**

```ts
import type { Finding } from '@fracta/core'
import type { ScanGrade } from './types'

const WEIGHT: Record<Finding['severity'], number> = {
  critical: 35, high: 20, medium: 10, low: 3, info: 0,
}

/** Determinístico: 100 menos o peso de cada finding, clampado a [0,100], mapeado p/ letra. */
export function grade(findings: Finding[]): { grade: ScanGrade; score: number } {
  const lost = findings.reduce((s, f) => s + (WEIGHT[f.severity] ?? 0), 0)
  const score = Math.max(0, Math.min(100, 100 - lost))
  const grade: ScanGrade =
    score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : score >= 20 ? 'E' : 'F'
  return { grade, score }
}
```

- [ ] **Step 4: Run — expect PASS**; **Step 5: Commit**

```bash
git add packages/web-scan/src/grader.ts packages/web-scan/src/__tests__/grader.test.ts
git commit -m "feat(web-scan): deterministic A–F grader"
```

---

## Task 8: Rate limiter (in-memory, injectable clock)

**Files:**
- Create: `packages/web-scan/src/rate-limiter.ts`
- Test: `packages/web-scan/src/__tests__/rate-limiter.test.ts`

- [ ] **Step 1: Failing test**

```ts
import { describe, it, expect } from 'vitest'
import { InMemoryRateLimiter } from '../rate-limiter'

describe('InMemoryRateLimiter', () => {
  it('allows up to the limit, then blocks within the window', () => {
    let now = 1000
    const rl = new InMemoryRateLimiter({ limit: 3, windowMs: 1000, now: () => now })
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(false)
  })
  it('resets after the window passes', () => {
    let now = 1000
    const rl = new InMemoryRateLimiter({ limit: 1, windowMs: 1000, now: () => now })
    expect(rl.check('ip1').allowed).toBe(true)
    expect(rl.check('ip1').allowed).toBe(false)
    now = 2100
    expect(rl.check('ip1').allowed).toBe(true)
  })
  it('isolates different IPs', () => {
    let now = 1000
    const rl = new InMemoryRateLimiter({ limit: 1, windowMs: 1000, now: () => now })
    expect(rl.check('a').allowed).toBe(true)
    expect(rl.check('b').allowed).toBe(true)
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `rate-limiter.ts`**

```ts
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
```

- [ ] **Step 4: Run — expect PASS**; **Step 5: Commit**

```bash
git add packages/web-scan/src/rate-limiter.ts packages/web-scan/src/__tests__/rate-limiter.test.ts
git commit -m "feat(web-scan): in-memory sliding-window rate limiter"
```

---

## Task 9: Scan store (SQLite, shareId + cache + emails)

**Files:**
- Create: `packages/web-scan/src/scan-store.ts`
- Test: `packages/web-scan/src/__tests__/scan-store.test.ts`

- [ ] **Step 1: Read `packages/store/src/index.ts`** to copy the exact `loadSqlite()`/`createRequire` pattern and constructor shape.

- [ ] **Step 2: Failing test**

```ts
import { describe, it, expect } from 'vitest'
import { SqliteScanStore } from '../scan-store'
import type { PassiveScanResult } from '../types'

const result = (url: string): PassiveScanResult => ({
  url, findings: [], grade: 'A', score: 100, verdict: 'ok', scannedAt: '2026-06-29T00:00:00.000Z',
})

describe('SqliteScanStore', () => {
  it('saves with an injected id and reads it back by shareId', () => {
    const s = new SqliteScanStore(':memory:')
    const id = s.save(result('https://a.example'), { genId: () => 'fixed-id' })
    expect(id).toBe('fixed-id')
    expect(s.getByShareId('fixed-id')?.url).toBe('https://a.example')
    expect(s.getByShareId('nope')).toBeNull()
  })
  it('returns a cached result within the TTL and null after', () => {
    const s = new SqliteScanStore(':memory:')
    let now = 10_000
    s.save(result('https://b.example'), { genId: () => 'b1', now: () => now })
    expect(s.getCached('https://b.example', 5_000, now)?.url).toBe('https://b.example')
    expect(s.getCached('https://b.example', 5_000, now + 6_000)).toBeNull()
  })
  it('stores captured emails', () => {
    const s = new SqliteScanStore(':memory:')
    s.saveEmail('a@b.com', 'waitlist')
    expect(s.countEmails()).toBe(1)
  })
})
```

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement `scan-store.ts`** (mirror `@fracta/store` loadSqlite)

```ts
import { createRequire } from 'node:module'
import { randomUUID } from 'node:crypto'
import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite'
import type { PassiveScanResult } from './types'

const nodeRequire = createRequire(import.meta.url)
function loadSqlite(): typeof import('node:sqlite') {
  try { return nodeRequire('node:sqlite') as typeof import('node:sqlite') }
  catch (err) { throw new Error(`node:sqlite indisponível (Node >= 22.5): ${(err as Error).message}`) }
}

export class SqliteScanStore {
  private readonly db: DatabaseSyncType
  constructor(path = './fracta-web.db') {
    const { DatabaseSync } = loadSqlite()
    this.db = new DatabaseSync(path)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scan (
        share_id TEXT PRIMARY KEY, url TEXT NOT NULL, scanned_at_ms INTEGER NOT NULL, result_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scan_url_ts ON scan (url, scanned_at_ms);
      CREATE TABLE IF NOT EXISTS email (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, context TEXT, at_ms INTEGER NOT NULL);
    `)
  }
  save(r: PassiveScanResult, opts: { genId?: () => string; now?: () => number } = {}): string {
    const id = (opts.genId ?? randomUUID)()
    const at = (opts.now ?? Date.now)()
    this.db.prepare('INSERT INTO scan (share_id, url, scanned_at_ms, result_json) VALUES (?, ?, ?, ?)')
      .run(id, r.url, at, JSON.stringify(r))
    return id
  }
  getByShareId(id: string): PassiveScanResult | null {
    const row = this.db.prepare('SELECT result_json FROM scan WHERE share_id = ?').get(id) as { result_json: string } | undefined
    return row ? (JSON.parse(row.result_json) as PassiveScanResult) : null
  }
  getCached(url: string, ttlMs: number, now = Date.now()): PassiveScanResult | null {
    const row = this.db.prepare('SELECT result_json, scanned_at_ms FROM scan WHERE url = ? ORDER BY scanned_at_ms DESC LIMIT 1')
      .get(url) as { result_json: string; scanned_at_ms: number } | undefined
    if (!row || now - row.scanned_at_ms > ttlMs) return null
    return JSON.parse(row.result_json) as PassiveScanResult
  }
  saveEmail(email: string, context = ''): void {
    this.db.prepare('INSERT INTO email (email, context, at_ms) VALUES (?, ?, ?)').run(email, context, Date.now())
  }
  countEmails(): number {
    return (this.db.prepare('SELECT COUNT(*) AS c FROM email').get() as { c: number }).c
  }
  close(): void { this.db.close() }
}
```

- [ ] **Step 5: Run — expect PASS** (`pnpm --filter @fracta/web-scan exec vitest run src/__tests__/scan-store.test.ts`); **Step 6: Commit**

```bash
git add packages/web-scan/src/scan-store.ts packages/web-scan/src/__tests__/scan-store.test.ts
git commit -m "feat(web-scan): SQLite scan store (shareId, cache, emails)"
```

---

## Task 10: PassiveScanner (orchestrator) + integration test

**Files:**
- Create: `packages/web-scan/src/passive-scanner.ts`
- Test: `packages/web-scan/src/__tests__/passive-scanner.test.ts`

- [ ] **Step 1: Read `packages/agents/headers/src/index.ts`** to confirm `HeadersAgent.run(scope)` and the `ScanScope`/`Target` shape it needs (`{ target: { name, url }, runId, depth }`). Build the scope accordingly.

- [ ] **Step 2: Write the integration test (against a local fixture server)**

```ts
import { describe, it, expect, afterAll } from 'vitest'
import http from 'node:http'
import { PassiveScanner } from '../passive-scanner'

const server = http.createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'sid=x' }) // sem flags + sem headers de segurança
  res.end('<html><body>sem privacidade</body></html>')
})
const base = await new Promise<string>((resolve) => {
  server.listen(0, '127.0.0.1', () => {
    const a = server.address()
    resolve(`http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}`)
  })
})
afterAll(() => server.close())

describe('PassiveScanner (integração)', () => {
  it('reúne findings passivos e grada o alvo de teste', async () => {
    // bypass do SSRF guard p/ permitir 127.0.0.1 SÓ no teste:
    const r = await new PassiveScanner({ allowPrivateForTest: true }).scan(base)
    expect(r.verdict).toBe('ok')
    expect(r.findings.length).toBeGreaterThan(0) // headers ausentes + cookie sem flags + lgpd-lite
    expect(['A','B','C','D','E','F']).toContain(r.grade)
  })
  it('veredito inconclusive p/ alvo inacessível', async () => {
    const r = await new PassiveScanner({ allowPrivateForTest: true }).scan('http://127.0.0.1:1') // porta fechada
    expect(r.verdict).toBe('inconclusive')
  })
})
```

- [ ] **Step 3: Run — expect FAIL**

- [ ] **Step 4: Implement `passive-scanner.ts`**

```ts
import { randomUUID } from 'node:crypto'
import type { Finding } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'
import { HeadersAgent } from '@fracta/agent-headers'
import { validateScanUrl } from './ssrf-guard'
import { findCookieIssues } from './cookie-check'
import { checkLgpdLite } from './lgpd-lite'
import { grade } from './grader'
import type { PassiveScanResult } from './types'

export class PassiveScanner {
  constructor(private readonly opts: { allowPrivateForTest?: boolean } = {}) {}

  async scan(input: string): Promise<PassiveScanResult> {
    // Em produção SEMPRE valida SSRF. allowPrivateForTest só p/ a integração local.
    const url = this.opts.allowPrivateForTest ? new URL(/^https?:\/\//.test(input) ? input : `https://${input}`) : await validateScanUrl(input)
    const saas = url.hostname
    const runId = randomUUID()

    const findings: Finding[] = []
    let reachable = false

    // 1) HEADERS agent (passivo) — reusa o motor existente.
    try {
      const headers = await new HeadersAgent().run({ target: { name: saas, url: url.toString() }, runId, depth: 'quick' } as never)
      findings.push(...headers)
      reachable = true
    } catch { /* inacessível ou skip — tratado pelo verdict */ }

    // 2) Resposta crua p/ cookies + LGPD-lite (1 GET passivo).
    try {
      const res = await new FractaHttpClient(url.toString()).request('/', { timeoutMs: 8000 })
      reachable = true
      const setCookie = (res.headers?.['set-cookie'] ?? []) as string[] | string
      findings.push(...findCookieIssues(Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [], saas, runId))
      findings.push(...checkLgpdLite(res.raw ?? '', saas, runId))
    } catch { /* idem */ }

    const verdict = reachable ? 'ok' : 'inconclusive'
    const { grade: g, score } = grade(findings)
    return { url: url.toString(), findings, grade: verdict === 'ok' ? g : 'F', score: verdict === 'ok' ? score : 0, verdict, scannedAt: new Date().toISOString() }
  }
}
```

> NOTE: confirm in Step 1 the actual property names on `FractaHttpClient`'s response (`headers`, `raw`) — read `packages/core/src/http-client.ts`. If they differ, adjust the two accessors above to match. Do not guess — read the file.

- [ ] **Step 5: Run — expect PASS** (`pnpm --filter @fracta/web-scan exec vitest run src/__tests__/passive-scanner.test.ts`)

- [ ] **Step 6: Commit**

```bash
git add packages/web-scan/src/passive-scanner.ts packages/web-scan/src/__tests__/passive-scanner.test.ts
git commit -m "feat(web-scan): PassiveScanner orchestrator (+ integration test)"
```

---

## Task 11: Public exports + full build/test

**Files:**
- Modify: `packages/web-scan/src/index.ts`

- [ ] **Step 1: Write `index.ts`**

```ts
export { validateScanUrl, isBlockedIp } from './ssrf-guard'
export type { AddressResolver } from './ssrf-guard'
export { PassiveScanner } from './passive-scanner'
export { grade } from './grader'
export { InMemoryRateLimiter } from './rate-limiter'
export type { RateLimitResult } from './rate-limiter'
export { SqliteScanStore } from './scan-store'
export type { PassiveScanResult, ScanGrade, ScanVerdict } from './types'
export { SsrfError } from './types'
```

- [ ] **Step 2: Full build + test of the package**

Run: `pnpm --filter @fracta/web-scan build && pnpm --filter @fracta/web-scan test`
Expected: build success; all tests pass.

- [ ] **Step 3: Whole-monorepo build + test (no regressions)**

Run: `pnpm build && pnpm test`
Expected: existing 40+ tests still pass; new web-scan tests pass.

- [ ] **Step 4: Commit**

```bash
git add packages/web-scan/src/index.ts
git commit -m "feat(web-scan): public exports; engine complete"
```

---

## Self-review (done while writing)

- **Spec coverage:** SsrfGuard ✅(T3–4), PassiveScanner/HEADERS+TLS-ish+cookies+LGPD-lite ✅(T5,6,10) — note: standalone `TlsCheck` (http→https redirect) is folded into PassiveScanner's reachability + HEADERS in v1; if a dedicated redirect check is wanted, add a small `tls-check.ts` task (deferred, low priority). Grader ✅(T7), RateLimiter ✅(T8), ScanStore shareId+cache+emails ✅(T9), honest inconclusive verdict ✅(T10). Intrusive agents excluded ✅ (none imported).
- **Placeholder scan:** none — every step has real code/commands. Two explicit "read the file first" steps (T9 loadSqlite, T10 FractaHttpClient response shape) are verification steps, not placeholders.
- **Type consistency:** `PassiveScanResult`/`ScanGrade`/`SsrfError` defined in T2 and used consistently in T7/T9/T10/T11; `grade()` signature stable.

## Next plans (after this one is implemented)
- **Plan 2 — `apps/web` (Next.js):** scan route handler wiring `@fracta/web-scan` (SSRF + rate-limit + cache + store), Home, `/r/[shareId]` result page, EmailCapture, ZapApiSupporter; UI built with the `interface-design` skill (dark + own accent, proof-driven, real-report visual).
- **Plan 3 — Infra:** Dockerfile for `apps/web`, GitHub Actions → GHCR, VPS pull, nginx server block for `fracta.pro` + Let's Encrypt, harden `default_server` to 444.
