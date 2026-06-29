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
