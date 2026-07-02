import { type NextRequest } from 'next/server'
import { getStore } from '@/lib/scan-store'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const GRADE_HEX: Record<string, string> = {
  A: '#34d399', B: '#a3e635', C: '#facc15', D: '#fb923c', E: '#f87171', F: '#ef4444',
}

function badgeSvg(grade: string | null): string {
  const letter = grade ?? '—'
  const color = grade ? GRADE_HEX[grade] ?? '#5b636b' : '#5b636b'
  const w = 150
  const h = 40
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" role="img" aria-label="Fracta: nota ${letter}">
  <rect width="${w}" height="${h}" rx="5" fill="#0a0b0d"/>
  <rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="4.5" fill="none" stroke="#1f2329"/>
  <svg x="8" y="7" width="26" height="26" viewBox="0 0 64 64">
    <defs><clipPath id="bf"><rect x="2" y="2" width="60" height="60" rx="15"/></clipPath></defs>
    <rect x="2" y="2" width="60" height="60" rx="15" fill="#111317"/>
    <g clip-path="url(#bf)">
      <path d="M30 -4 L30 28 L40 34 L40 68" stroke="#3ad6cf" stroke-width="7" fill="none"/>
      <path d="M30 23 L21 33" stroke="#3ad6cf" stroke-width="5" fill="none"/>
    </g>
    <rect x="2.5" y="2.5" width="59" height="59" rx="14.5" fill="none" stroke="#2b3038" stroke-width="2"/>
  </svg>
  <text x="42" y="25" font-family="ui-monospace,monospace" font-size="13" font-weight="600" fill="#e7e9ec">Fracta</text>
  <rect x="${w - 40}" y="8" width="32" height="24" rx="4" fill="${color}1a" stroke="${color}55"/>
  <text x="${w - 24}" y="25" font-family="ui-monospace,monospace" font-size="15" font-weight="600" fill="${color}" text-anchor="middle">${letter}</text>
</svg>`
}

export function GET(_req: NextRequest, { params }: { params: { shareId: string } }) {
  const store = getStore()
  const result = store?.getByShareId(params.shareId) ?? null
  const grade = result ? result.grade : null
  // Medição agregada: um badge embutido foi servido (sinal de distribuição/backlink).
  if (result) store?.bump('badge_served')
  return new Response(badgeSvg(grade), {
    status: result ? 200 : 404,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  })
}
