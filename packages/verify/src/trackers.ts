export interface TrackerHit {
  name: string
  requests: string[]
}

/** Assinaturas de trackers observáveis em REQUISIÇÕES de runtime (não em HTML estático). */
const RUNTIME_TRACKERS: Array<{ name: string; re: RegExp }> = [
  { name: 'Google Analytics 4', re: /google-analytics\.com\/g\/collect|googletagmanager\.com\/gtag\/js/i },
  { name: 'Google Tag Manager', re: /googletagmanager\.com\/gtm\.js/i },
  { name: 'Meta Pixel (Facebook)', re: /connect\.facebook\.net|facebook\.com\/tr(\?|\b)/i },
  { name: 'TikTok Pixel', re: /analytics\.tiktok\.com/i },
  { name: 'LinkedIn Insight', re: /px\.ads\.linkedin\.com|snap\.licdn\.com/i },
  { name: 'Microsoft Clarity', re: /clarity\.ms/i },
  { name: 'Hotjar', re: /static\.hotjar\.com|script\.hotjar\.com/i },
]

/** Dada a lista de URLs de requisição capturadas, agrupa por tracker conhecido. */
export function classifyTrackers(requestUrls: string[]): TrackerHit[] {
  const byName = new Map<string, string[]>()
  for (const url of requestUrls) {
    for (const t of RUNTIME_TRACKERS) {
      if (t.re.test(url)) {
        const arr = byName.get(t.name) ?? []
        arr.push(url)
        byName.set(t.name, arr)
      }
    }
  }
  return [...byName.entries()].map(([name, requests]) => ({ name, requests }))
}
