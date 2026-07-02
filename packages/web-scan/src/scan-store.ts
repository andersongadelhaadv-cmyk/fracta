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
      CREATE TABLE IF NOT EXISTS metric (name TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (name, day));
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

  /**
   * Medição first-party: incrementa um contador AGREGADO de evento de produto por dia
   * (UTC). Só conta EVENTOS (scan, view de relatório, badge servido, e-mail) — nunca
   * identidade: zero IP, cookie ou fingerprint. Honra a promessa "sem perfilamento".
   */
  bump(name: string, opts: { now?: () => number } = {}): void {
    const at = (opts.now ?? Date.now)()
    const day = new Date(at).toISOString().slice(0, 10) // YYYY-MM-DD (UTC)
    this.db.prepare(
      'INSERT INTO metric (name, day, count) VALUES (?, ?, 1) ON CONFLICT(name, day) DO UPDATE SET count = count + 1',
    ).run(name, day)
  }

  /**
   * Funil agregado: totais por evento (somados sobre todos os dias), a janela dos
   * últimos `windowDays` dias, e os totais de escala derivados das tabelas de dados
   * (scans persistidos, e-mails). Nenhum dado pessoal — só números.
   */
  metricsSummary(opts: { now?: () => number; windowDays?: number } = {}): {
    events: Record<string, number>
    recent: Record<string, number>
    emails: number
    scansPersisted: number
    windowDays: number
  } {
    const now = (opts.now ?? Date.now)()
    const windowDays = opts.windowDays ?? 7
    const sumRows = this.db.prepare('SELECT name, SUM(count) AS c FROM metric GROUP BY name')
      .all() as Array<{ name: string; c: number }>
    const events: Record<string, number> = {}
    for (const r of sumRows) events[r.name] = Number(r.c)

    const since = new Date(now - windowDays * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)
    const recentRows = this.db.prepare('SELECT name, SUM(count) AS c FROM metric WHERE day >= ? GROUP BY name')
      .all(since) as Array<{ name: string; c: number }>
    const recent: Record<string, number> = {}
    for (const r of recentRows) recent[r.name] = Number(r.c)

    const scansPersisted = (this.db.prepare('SELECT COUNT(*) AS c FROM scan').get() as { c: number }).c
    return { events, recent, emails: this.countEmails(), scansPersisted, windowDays }
  }

  /**
   * Assinaturas de monitoramento (#4): e-mails capturados no relatório
   * (`context = 'result:<shareId>'`) juntados à URL do scan — só quem tem um alvo
   * concreto p/ re-escanear. Deduplicado por (email, shareId). Contextos sem alvo
   * ('home', 'waitlist') ficam de fora. É o INPUT do resumo semanal por e-mail;
   * o envio em si é gated (infra + consentimento LGPD + opt-out).
   */
  listSubscriptions(): Array<{ email: string; shareId: string; url: string }> {
    return this.db.prepare(
      `SELECT DISTINCT e.email AS email, s.share_id AS shareId, s.url AS url
       FROM email e JOIN scan s ON e.context = 'result:' || s.share_id
       ORDER BY e.email, s.share_id`,
    ).all() as Array<{ email: string; shareId: string; url: string }>
  }

  close(): void { this.db.close() }
}
