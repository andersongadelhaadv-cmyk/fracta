import Link from 'next/link'
import type { ScanGrade } from '@fracta/web-scan'
import { gradeColor } from '@/lib/grade-ui'

/**
 * Prova social HONESTA: as notas A–F que o próprio Fracta deu à frota de SaaS da
 * PreviusIA. Cada card abre o relatório REAL (/r/[shareId]) — infalsificável. Não
 * é logo-vitrine ("confie em nós"); é "verifique você mesmo" — que é o produto.
 * Notas/relatórios snapshot; o link "rode agora" re-checa ao vivo.
 */
const FLEET: Array<{ name: string; domain: string; grade: ScanGrade; shareId: string }> = [
  { name: 'ADVOCUS', domain: 'advocus.com.br', grade: 'A', shareId: '9cb5cb8f-9709-45f1-ae56-042ecd9f1287' },
  { name: 'Veredicto', domain: 'veredicto.tech', grade: 'A', shareId: '58daa64d-1a89-452a-afe5-fe4be04eebda' },
  { name: 'DoutorINSS', domain: 'doutorinss.com', grade: 'A', shareId: 'f30b36bd-b738-4bce-9902-b4fc3fcc3822' },
  { name: 'VeriJus', domain: 'verijus.com.br', grade: 'A', shareId: 'ea8ee7a7-bd7d-4958-b29a-e4467d44cc72' },
  { name: 'Pleita', domain: 'pleita.pro', grade: 'A', shareId: 'c5d3c380-e5b9-4887-969e-d71706a8515b' },
  { name: 'PreviusIA', domain: 'previusia.com.br', grade: 'A', shareId: 'c73eca1e-f08b-4806-a5d9-21f94f91b659' },
]

function GradeChip({ grade }: { grade: ScanGrade }) {
  const c = gradeColor(grade)
  return (
    <span
      className="flex h-9 w-9 shrink-0 items-center justify-center rounded font-mono text-lg font-semibold"
      style={{ color: c, border: `1px solid ${c}55`, background: `${c}12` }}
    >
      {grade}
    </span>
  )
}

export function FleetProof() {
  return (
    <section className="border-b border-border">
      <div className="mx-auto max-w-content px-5 py-14">
        <p className="font-mono text-xs uppercase tracking-wide text-accent">a prova</p>
        <h2 className="mt-3 max-w-2xl text-2xl font-semibold tracking-tight text-text sm:text-3xl">
          Não confie na nossa palavra.<br className="hidden sm:block" /> Veja as notas que demos à nossa própria frota.
        </h2>
        <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
          Antes de avaliar o seu, o Fracta audita os SaaS que a PreviusIA opera. Estas são notas <span className="text-text">reais</span>,
          geradas por este mesmo scanner — clique e veja o relatório completo. Depois, rode no seu site.
        </p>

        <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {FLEET.map((s) => (
            <Link
              key={s.domain}
              href={`/r/${s.shareId}`}
              className="group flex items-center gap-4 rounded-md border border-border bg-surface px-4 py-4 transition-colors hover:border-border-strong"
            >
              <GradeChip grade={s.grade} />
              <span className="min-w-0 flex-1">
                <span className="block font-mono text-sm font-medium text-text">{s.name}</span>
                <span className="block truncate font-mono text-xs text-faint">{s.domain}</span>
              </span>
              <span className="font-mono text-xs text-faint transition-colors group-hover:text-accent">ver →</span>
            </Link>
          ))}
        </div>

        <p className="mt-6 font-mono text-xs text-faint">
          Notas e relatórios são snapshots da auditoria. O Fracta é honesto até consigo: o que ainda não está A entra na fila de correção, não é escondido.
        </p>
      </div>
    </section>
  )
}
