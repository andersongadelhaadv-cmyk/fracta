import type { Finding } from '@fracta/core'

export type ScanGrade = 'A' | 'B' | 'C' | 'D' | 'E' | 'F'

/** Veredito honesto: 'ok' = alvo exercido; 'inconclusive' = inacessível (ausência ≠ seguro). */
export type ScanVerdict = 'ok' | 'inconclusive'

/** Status de um check individual — transparência sobre o que rodou (ou não). */
export interface ScanCheck {
  name: string
  status: 'ok' | 'skipped'
}

export interface PassiveScanResult {
  url: string
  findings: Finding[]
  /** null quando inconclusivo: NUNCA marcamos 'F' num alvo que não conseguimos avaliar. */
  grade: ScanGrade | null
  /** null quando inconclusivo. 0–100 caso contrário. */
  score: number | null
  verdict: ScanVerdict
  /** Quais checks rodaram — um check pulado NÃO vira "seguro". */
  checks: ScanCheck[]
  scannedAt: string // ISO
}

/** Erro tipado de validação SSRF — a URL foi recusada antes de qualquer fetch. */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SsrfError'
  }
}
