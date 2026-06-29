import 'server-only'
import { SqliteScanStore } from '@fracta/web-scan'
import { DB_PATH } from './config'

type Store = SqliteScanStore | null

// Singleton via globalThis p/ sobreviver ao HMR do dev e não reabrir o DB a cada request.
const g = globalThis as unknown as { __fractaStore?: Store }

/**
 * Store com degradação graciosa: se `node:sqlite` faltar (Node < 22.5), o scan
 * ainda roda — só não persiste/compartilha. Falha de persistência nunca derruba
 * a detecção (regra do core).
 */
export function getStore(): Store {
  if (g.__fractaStore !== undefined) return g.__fractaStore
  try {
    g.__fractaStore = new SqliteScanStore(DB_PATH)
  } catch (e) {
    console.warn('[fracta-web] store indisponível, seguindo sem persistência:', (e as Error).message)
    g.__fractaStore = null
  }
  return g.__fractaStore
}
