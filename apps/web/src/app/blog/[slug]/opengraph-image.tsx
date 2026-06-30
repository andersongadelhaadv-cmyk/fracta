import { ImageResponse } from 'next/og'
import { getAllSlugs, getPostBySlug } from '@/lib/blog'

export const alt = 'Fracta — segurança web e LGPD'
export const size = { width: 1200, height: 630 }
export const contentType = 'image/png'

export function generateStaticParams() {
  return getAllSlugs().map((slug) => ({ slug }))
}

// Chakra Petch carregada explicitamente (mesma razão do OG de resultado: evita o
// bug de font default do @vercel/og; fallback p/ default se o fetch falhar).
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

export default async function Image({ params }: { params: { slug: string } }) {
  const post = await getPostBySlug(params.slug)
  const title = post?.title ?? 'Fracta — segurança web e LGPD'
  const kicker = post?.tags?.[0]?.toUpperCase() ?? 'SEGURANÇA · LGPD'
  const titleSize = title.length > 70 ? 52 : title.length > 45 ? 64 : 76
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
        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 5, background: '#3ad6cf' }} />

        <div style={{ display: 'flex', fontSize: 26, color: '#3ad6cf', letterSpacing: 3 }}>
          BLOG · {kicker}
        </div>

        <div style={{ display: 'flex', fontSize: titleSize, fontWeight: 700, color: '#e7e9ec', lineHeight: 1.1 }}>
          {title}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', fontSize: 34, fontWeight: 700 }}>
            <span style={{ color: '#e7e9ec' }}>Fracta</span>
            <span style={{ color: '#3ad6cf' }}>.</span>
          </div>
          <div style={{ display: 'flex', fontSize: 24, color: '#5b636b' }}>analise seu site grátis · fracta.pro</div>
        </div>
      </div>
    ),
    { ...size, fonts: fonts.length ? fonts : undefined },
  )
}
