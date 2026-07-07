import type { PassiveScanResult } from './types.js'
import { diffScans, type ScanDiff } from './diff.js'

/**
 * Motor de monitoramento contínuo (#4): re-escaneia cada assinatura ativa, compara com
 * o último scan salvo e emite um alerta SÓ quando há regressão REAL. Puro/injetável —
 * não envia nada (a notificação é do chamador). Honra os invariantes de honestidade:
 * baseline (1º scan) não alerta; nota nula/inconclusiva nunca vira regressão inventada;
 * "ainda ruim" (mesma nota+achados) não re-notifica; scan que falha é pulado, não crash.
 */
export interface MonitorSubscription {
  id: number
  email: string
  url: string
  unsubToken: string
  lastNotifiedScanId: string | null
}

export interface MonitorDeps {
  listActive(): MonitorSubscription[]
  /** Último scan salvo do alvo (o "anterior"), ou null se nunca escaneado. */
  getLastScan(url: string): { shareId: string; result: PassiveScanResult } | null
  /** Re-escaneia o alvo agora. Pode lançar (alvo fora do ar) → pulamos. */
  scan(url: string): Promise<PassiveScanResult>
  /** Persiste o scan novo; devolve o shareId (link do relatório). */
  saveScan(result: PassiveScanResult): string
  markNotified(id: number, shareId: string): void
}

export interface Alert {
  subscription: Pick<MonitorSubscription, 'id' | 'email' | 'url' | 'unsubToken'>
  diff: ScanDiff
  /** shareId do scan NOVO (link `/r/<shareId>` no e-mail). */
  shareId: string
}

export async function runMonitor(deps: MonitorDeps): Promise<Alert[]> {
  const alerts: Alert[] = []
  for (const sub of deps.listActive()) {
    const prev = deps.getLastScan(sub.url) // ANTES de salvar o novo, senão pegaríamos o próprio

    let current: PassiveScanResult
    try {
      current = await deps.scan(sub.url)
    } catch {
      continue // alvo inacessível — pula honesto (ausência ≠ regressão)
    }
    const shareId = deps.saveScan(current)

    if (!prev) continue // baseline: primeiro scan, nada com que comparar

    const diff = diffScans(prev.result, current)
    if (diff.regressed) {
      alerts.push({
        subscription: { id: sub.id, email: sub.email, url: sub.url, unsubToken: sub.unsubToken },
        diff,
        shareId,
      })
      deps.markNotified(sub.id, shareId)
    }
  }
  return alerts
}
