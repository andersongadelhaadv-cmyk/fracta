import { createRequire } from 'node:module'
import { randomUUID } from 'node:crypto'
import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite'
import type { PassiveScanResult } from './types.js'

// node:sqlite é builtin recente (Node >= 22.5); carregado via require em runtime
// para escapar da análise estática do bundler (vite/vitest), igual ao @fracta/store.
const nodeRequire = createRequire(import.meta.url)
function loadSqlite(): typeof import('node:sqlite') {
  try {
    return nodeRequire('node:sqlite') as typeof import('node:sqlite')
  } catch (err) {
    throw new Error(
      `node:sqlite indisponível (requer Node >= 22.5; rodando ${process.version}): ${(err as Error).message}`,
    )
  }
}

/**
 * Persistência do scanner web: resultados por share-id, cache por URL e emails capturados.
 * Falha de persistência nunca deve derrubar o scan (degradação graciosa, regra do core).
 * Use `:memory:` para testes.
 */
export class SqliteScanStore {
  private readonly db: DatabaseSyncType
  constructor(path = './fracta-web.db', opts: { retentionDays?: number } = {}) {
    const { DatabaseSync } = loadSqlite()
    this.db = new DatabaseSync(path)
    if (path !== ':memory:') {
      try { this.db.exec('PRAGMA journal_mode = WAL') } catch { /* fs read-only: segue sem WAL */ }
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scan (
        share_id TEXT PRIMARY KEY, url TEXT NOT NULL, scanned_at_ms INTEGER NOT NULL, result_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scan_url_ts ON scan (url, scanned_at_ms);
      CREATE TABLE IF NOT EXISTS email (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, context TEXT, at_ms INTEGER NOT NULL);
    `)
    // Retenção: limpa scans antigos no boot (limita crescimento de disco num endpoint público).
    const days = opts.retentionDays ?? 90
    if (days > 0) {
      try { this.pruneOlderThan(days * 24 * 60 * 60 * 1000) } catch { /* best-effort */ }
    }
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
    return this.getCachedEntry(url, ttlMs, now)?.result ?? null
  }

  /**
   * Como getCached, mas retorna também o share_id existente — para reusar o link
   * compartilhável no cache-hit em vez de mintar uma nova linha a cada acesso
   * (evita crescimento ilimitado + geração gratuita de shareIds).
   */
  getCachedEntry(url: string, ttlMs: number, now = Date.now()): { shareId: string; result: PassiveScanResult } | null {
    const row = this.db.prepare('SELECT share_id, result_json, scanned_at_ms FROM scan WHERE url = ? ORDER BY scanned_at_ms DESC LIMIT 1')
      .get(url) as { share_id: string; result_json: string; scanned_at_ms: number } | undefined
    if (!row || now - row.scanned_at_ms > ttlMs) return null
    return { shareId: row.share_id, result: JSON.parse(row.result_json) as PassiveScanResult }
  }

  /** Remove scans mais antigos que `maxAgeMs`. Retorna quantas linhas saíram. */
  pruneOlderThan(maxAgeMs: number, now = Date.now()): number {
    const res = this.db.prepare('DELETE FROM scan WHERE scanned_at_ms < ?').run(now - maxAgeMs)
    return Number(res.changes ?? 0)
  }
  saveEmail(email: string, context = '', opts: { now?: () => number } = {}): void {
    const at = (opts.now ?? Date.now)()
    this.db.prepare('INSERT INTO email (email, context, at_ms) VALUES (?, ?, ?)').run(email, context, at)
  }
  /** Remove e-mails mais antigos que `maxAgeMs`. Retorna quantas linhas saíram (G007 LGPD). */
  pruneEmailsOlderThan(maxAgeMs: number, now = Date.now()): number {
    const res = this.db.prepare('DELETE FROM email WHERE at_ms < ?').run(now - maxAgeMs)
    return Number(res.changes ?? 0)
  }
  countEmails(): number {
    return (this.db.prepare('SELECT COUNT(*) AS c FROM email').get() as { c: number }).c
  }
  close(): void { this.db.close() }
}
