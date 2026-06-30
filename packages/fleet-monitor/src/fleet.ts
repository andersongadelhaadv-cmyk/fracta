export interface FleetTarget {
  domain: string
  label: string
}

/**
 * Superfície pública da frota PreviusIA monitorada de forma passiva.
 * Só homepages de produtos (apex) — sem api./www./subdomínios internos.
 * Anacrim foi aposentado (410) e sai da lista de propósito.
 */
export const FLEET: FleetTarget[] = [
  { domain: 'fracta.pro', label: 'Fracta' },
  { domain: 'advocus.com.br', label: 'ADVOCUS' },
  { domain: 'veredicto.tech', label: 'Veredicto' },
  { domain: 'doutorinss.com', label: 'DoutorINSS' },
  { domain: 'pleita.pro', label: 'Pleita' },
  { domain: 'praetori.com.br', label: 'Praetori' },
  { domain: 'verijus.com.br', label: 'VeriJus' },
  { domain: 'tribux.pro', label: 'Tribux' },
  { domain: 'mftd.com.br', label: 'MFTD' },
  { domain: 'zappbot.pro', label: 'ZappBot' },
  { domain: 'zap-api.tech', label: 'ZAP-API' },
  { domain: 'juribase.com.br', label: 'JuriBase' },
  { domain: 'iatech.tech', label: 'IATech' },
  { domain: 'previusia.com.br', label: 'PreviusIA' },
  { domain: 'meajudadoutores.com.br', label: 'Me Ajuda Doutores' },
  { domain: 'andersongadelha.adv.br', label: 'Anderson Gadelha' },
]
