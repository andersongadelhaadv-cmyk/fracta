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
  const w = 132
  const h = 40
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" role="img" aria-label="Fracta: nota ${letter}">
  <rect width="${w}" height="${h}" rx="5" fill="#0a0b0d"/>
  <rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="4.5" fill="none" stroke="#1f2329"/>
  <text x="14" y="25" font-family="ui-monospace,monospace" font-size="13" fill="#8b9299">fracta</text>
  <circle cx="61" cy="22" r="1.6" fill="#3ad6cf"/>
  <rect x="92" y="8" width="32" height="24" rx="4" fill="${color}1a" stroke="${color}55"/>
  <text x="108" y="25" font-family="ui-monospace,monospace" font-size="15" font-weight="600" fill="${color}" text-anchor="middle">${letter}</text>
</svg>`
}

export function GET(_req: NextRequest, { params }: { params: { shareId: string } }) {
  const store = getStore()
  const result = store?.getByShareId(params.shareId) ?? null
  const grade = result ? result.grade : null
  return new Response(badgeSvg(grade), {
    status: result ? 200 : 404,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  })
}
