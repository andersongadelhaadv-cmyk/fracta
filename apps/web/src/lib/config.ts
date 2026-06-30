/** Cache de resultado por URL (rescan recente é servido do cache). */
export const CACHE_TTL_MS = 60 * 60 * 1000 // 1h

/** Rate-limit por IP (anti-abuso/recon). Conservador no v1. */
export const RATE_LIMIT = { limit: 10, windowMs: 10 * 60 * 1000 } // 10 análises / 10 min

/** Caminho do SQLite (volume na VPS). */
export const DB_PATH = process.env.FRACTA_WEB_DB ?? './fracta-web.db'

export const REPO_URL = 'https://github.com/andersongadelhaadv-cmyk/fracta'
export const ZAP_API_URL = 'https://zap-api.tech'
export const PREVIUSIA_URL = 'https://previusia.com.br'
