/** O que a casca do browser coleta da página para alimentar a detecção pura. */
export interface CmpProbe {
  /** Nomes de globais presentes em `window` (ex.: 'OneTrust', '__tcfapi'). */
  globals: string[]
  /** Seletores de CMP que casaram no DOM. */
  selectorsMatched: string[]
}

export interface CmpDetection {
  detected: boolean
  vendor?: string
}

/** Globais fortes de CMP → nome do vendor. */
export const CMP_GLOBALS: Array<{ key: string; vendor: string }> = [
  { key: 'OneTrust', vendor: 'OneTrust' },
  { key: 'Cookiebot', vendor: 'Cookiebot' },
  { key: 'Didomi', vendor: 'Didomi' },
  { key: '__tcfapi', vendor: 'IAB TCF' },
  { key: 'UC_UI', vendor: 'Usercentrics' },
]

/** Seletores de banner de CMP (o browser testa `document.querySelector`) → vendor. */
export const CMP_SELECTORS: Array<{ selector: string; vendor: string }> = [
  { selector: '#onetrust-banner-sdk', vendor: 'OneTrust' },
  { selector: '#CybotCookiebotDialog', vendor: 'Cookiebot' },
  { selector: '#usercentrics-root', vendor: 'Usercentrics' },
  { selector: '#didomi-host', vendor: 'Didomi' },
]

/** Detecção determinística de CMP a partir da sonda de runtime. Sem heurística fraca. */
export function detectCmp(probe: CmpProbe): CmpDetection {
  for (const g of CMP_GLOBALS) {
    if (probe.globals.includes(g.key)) return { detected: true, vendor: g.vendor }
  }
  for (const s of CMP_SELECTORS) {
    if (probe.selectorsMatched.includes(s.selector)) return { detected: true, vendor: s.vendor }
  }
  return { detected: false }
}
