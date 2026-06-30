import { ImageResponse } from 'next/og'
import { getStore } from '@/lib/scan-store'

// Node runtime: o store usa node:sqlite (não roda no Edge).
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
export const alt = 'Relatório de segurança e LGPD — Fracta'
export const size = { width: 1200, height: 630 }
export const contentType = 'image/png'

const GRADE_HEX: Record<string, string> = {
  A: '#34d399', B: '#a3e635', C: '#facc15', D: '#fb923c', E: '#f87171', F: '#ef4444',
}
const NA = '#5b636b'

function hostOf(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return url
  }
}

// Fonte da marca (Chakra Petch) carregada uma vez por processo. Fornecer a fonte
// explicitamente também evita o bug de path do @vercel/og no Windows (default font
// = "Invalid URL"). Fallback p/ a fonte default se o fetch falhar (funciona no Linux).
type FontEntry = { name: string; data: ArrayBuffer; weight: 400 | 700; style: 'normal' }
let fontsCache: FontEntry[] | null = null
const FONT_BASE = 'https://raw.githubusercontent.com/google/fonts/main/ofl/chakrapetch'
async function loadFonts(): Promise<FontEntry[]> {
  if (fontsCache) return fontsCache
  try {
    const [regular, bold] = await Promise.all([
      fetch(`${FONT_BASE}/ChakraPetch-Regular.ttf`).then((r) => r.arrayBuffer()),
      fetch(`${FONT_BASE}/ChakraPetch-Bold.ttf`).then((r) => r.arrayBuffer()),
    ])
    fontsCache = [
      { name: 'Chakra Petch', data: regular, weight: 400, style: 'normal' },
      { name: 'Chakra Petch', data: bold, weight: 700, style: 'normal' },
    ]
  } catch {
    fontsCache = []
  }
  return fontsCache
}

export default async function Image({ params }: { params: { shareId: string } }) {
  const result = getStore()?.getByShareId(params.shareId) ?? null
  const grade = result?.grade ?? null
  const color = grade ? GRADE_HEX[grade] ?? NA : NA
  const host = result ? hostOf(result.url) : 'fracta.pro'
  const letter = grade ?? (result ? '—' : '?')
  const label = result ? (grade ? `Nota ${grade}` : 'Inconclusivo — não avaliado') : 'Scanner de segurança e LGPD'
  const hostSize = host.length > 26 ? 56 : host.length > 18 ? 68 : 80
  const fonts = await loadFonts()

  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          background: '#0a0b0d',
          padding: 72,
          position: 'relative',
          fontFamily: 'Chakra Petch',
        }}
      >
        {/* hairline cyan no topo */}
        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 5, background: '#3ad6cf' }} />

        {/* linha principal: anel da nota + texto */}
        <div style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
          <div
            style={{
              display: 'flex',
              width: 300,
              height: 300,
              borderRadius: 300,
              border: `16px solid ${color}`,
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: 72,
            }}
          >
            <div style={{ display: 'flex', fontSize: 168, fontWeight: 700, color }}>{letter}</div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
            <div style={{ display: 'flex', fontSize: 26, color: '#3ad6cf', letterSpacing: 3 }}>
              RELATÓRIO PASSIVO · FRACTA.PRO
            </div>
            <div style={{ display: 'flex', fontSize: hostSize, fontWeight: 700, color: '#e7e9ec', marginTop: 18 }}>
              {host}
            </div>
            <div style={{ display: 'flex', fontSize: 44, fontWeight: 600, color, marginTop: 10 }}>{label}</div>
            <div style={{ display: 'flex', fontSize: 26, color: '#8b9299', marginTop: 26 }}>
              headers · TLS · cookies · LGPD — detecção determinística
            </div>
          </div>
        </div>

        {/* rodapé */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', fontSize: 34, fontWeight: 700 }}>
            <span style={{ color: '#e7e9ec' }}>Fracta</span>
            <span style={{ color: '#3ad6cf' }}>.</span>
          </div>
          <div style={{ display: 'flex', fontSize: 24, color: '#5b636b' }}>rode no seu site, sem cadastro</div>
        </div>
      </div>
    ),
    { ...size, fonts: fonts.length ? fonts : undefined },
  )
}
