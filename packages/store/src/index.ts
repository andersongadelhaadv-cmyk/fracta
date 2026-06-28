import { createRequire } from 'node:module'
import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite'
import type { Finding, FindingStatus, FindingStore, AuditReport } from '@fracta/core'

// `node:sqlite` é um builtin recente: o vite/vitest 5.x não o reconhece e tenta
// resolver um pacote `sqlite` inexistente ao analisar um `import` estático. Carregar
// via require em runtime evita a análise estática do bundler e funciona em build e teste.
const nodeRequire = createRequire(import.meta.url)

/**
 * Carrega `node:sqlite` (builtin Node >= 22.5) SOB DEMANDA, dentro do construtor.
 * Em runtimes mais antigos (ex.: Node 20 na VPS) o módulo não existe; aqui isso vira
 * um Error claro e CATCHÁVEL, em vez de derrubar o processo na avaliação do módulo —
 * assim `import { SqliteFindingStore }` nunca quebra um entrypoint. Quem constrói o
 * store decide degradar para "sem estado" (regra Fase 2: falha de persistência nunca
 * derruba a detecção).
 */
function loadSqlite(): typeof import('node:sqlite') {
  try {
    return nodeRequire('node:sqlite') as typeof import('node:sqlite')
  } catch (err) {
    throw new Error(
      `node:sqlite indisponível (requer Node >= 22.5; rodando ${process.version}): ` +
        `${(err as Error).message}`,
    )
  }
}

/**
 * Persistência do histórico de findings — habilita regressão e supressão entre
 * execuções (Fase 2 do REFACTOR_PLAN). Usa o SQLite embutido do Node (`node:sqlite`,
 * Node >= 22.5): sem servidor e sem dependência nativa para compilar, o que casa com
 * o design "no port" do Fracta (CLI/MCP) e mantém a fragilidade baixa. Use `:memory:`
 * para testes.
 */
export class SqliteFindingStore implements FindingStore {
  private readonly db: DatabaseSyncType

  constructor(path = './fracta-state.db') {
    const { DatabaseSync } = loadSqlite()
    this.db = new DatabaseSync(path)
    if (path !== ':memory:') {
      try { this.db.exec('PRAGMA journal_mode = WAL') } catch { /* fs read-only: segue sem WAL */ }
    }
    this.migrate()
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS finding_history (
        id          TEXT NOT NULL,
        saas        TEXT NOT NULL,
        camada      TEXT NOT NULL,
        severidade  TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        resolved    INTEGER NOT NULL DEFAULT 0,
        suppressed  INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (id, saas)
      );
      CREATE INDEX IF NOT EXISTS idx_fh_saas_camada ON finding_history (saas, camada);

      CREATE TABLE IF NOT EXISTS audit_run (
        id          TEXT PRIMARY KEY,
        saas        TEXT NOT NULL,
        timestamp   TEXT NOT NULL,
        report_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_ar_saas_ts ON audit_run (saas, timestamp);
    `)
  }

  applyStatus(saas: string, findings: Finding[], suppressions: string[] = []): Finding[] {
    const supp = new Set(suppressions)
    const now = new Date().toISOString()

    const getRow = this.db.prepare('SELECT resolved FROM finding_history WHERE id = ? AND saas = ?')
    const upsert = this.db.prepare(`
      INSERT INTO finding_history (id, saas, camada, severidade, first_seen, last_seen, resolved, suppressed)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?)
      ON CONFLICT(id, saas) DO UPDATE SET
        last_seen = excluded.last_seen,
        resolved = 0,
        severidade = excluded.severidade,
        suppressed = excluded.suppressed
    `)
    const listOpen = this.db.prepare('SELECT id FROM finding_history WHERE saas = ? AND resolved = 0')
    const markResolved = this.db.prepare('UPDATE finding_history SET resolved = 1 WHERE id = ? AND saas = ?')

    const result: Finding[] = []
    const presentIds = new Set<string>()

    this.db.exec('BEGIN')
    try {
      for (const f of findings) {
        presentIds.add(f.id)
        const prev = getRow.get(f.id, saas) as { resolved: number } | undefined
        const isSuppressed = supp.has(f.id)

        let status: FindingStatus
        if (isSuppressed) status = 'suppressed'
        else if (prev && prev.resolved === 1) status = 'regression' // voltou após resolvido
        else status = 'open'

        upsert.run(
          f.id,
          saas,
          f.camada ?? f.category,
          f.severity,
          now,
          now,
          isSuppressed ? 1 : 0,
        )
        result.push({ ...f, status })
      }

      // Findings que estavam abertos no histórico e NÃO apareceram agora → resolvidos.
      // Se voltarem num run futuro, serão detectados como regressão.
      const openRows = listOpen.all(saas) as Array<{ id: string }>
      for (const row of openRows) {
        if (!presentIds.has(row.id)) markResolved.run(row.id, saas)
      }

      this.db.exec('COMMIT')
    } catch (err) {
      this.db.exec('ROLLBACK')
      throw err
    }

    return result
  }

  recordRun(report: AuditReport): void {
    this.db
      .prepare('INSERT INTO audit_run (id, saas, timestamp, report_json) VALUES (?, ?, ?, ?)')
      .run(report.runId, report.saas, report.timestamp, JSON.stringify(report))
  }

  close(): void {
    this.db.close()
  }
}
