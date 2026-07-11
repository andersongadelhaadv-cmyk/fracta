// Matcher do oráculo (recall dos fixtures). Um item plantado é DETECTADO se algum finding o
// aponta por (arquivo por sufixo) + (linha dentro de tolerância, OU finding sem linha = nível-arquivo).
//
// Decisão de honestidade: NÃO exigimos concordância de categoria. O Fracta pode flagrar um segredo
// plantado via o agente STACK (camada 'code') em vez de SECRETS — creditar a detecção
// independentemente da "pista" interna é o recall honesto. A concordância de categoria é REPORTADA
// como estatística (categoryAgree), não usada como porteira.
const LINE_TOL = 3
const norm = (s) => String(s || '').replace(/\\/g, '/').toLowerCase()
const fileMatch = (found, truth) => { const a = norm(found), b = norm(truth); return !!a && !!b && (a.endsWith(b) || a.endsWith('/' + b)) }

// Muitos findings cravam o arquivo:linha no TÍTULO (ex.: "…: src/auth.ts:2"). Extrai dali quando
// location falta. NÃO usa a evidência: ela cita arquivos incidentais (ex.: "package.json sem bcrypt")
// que sequestrariam a localização e bloqueariam o casamento por sinal. Só location + título contam.
function locFromText(f) {
  if (f.location?.file) return { file: f.location.file, line: f.location.line ?? null }
  const m = String(f.title || '').replace(/\\/g, '/').match(/([\w./-]+\.(?:ts|tsx|js|mjs|prisma|env|json|py|php))(?::(\d+))?/i)
  if (m) return { file: m[1], line: m[2] ? Number(m[2]) : null }
  return { file: null, line: null }
}

// Mapeia a categoria interna do Fracta → categoria do oráculo (só p/ a stat de concordância).
function oracleCategory(f) {
  const camada = norm(f.camada)
  const agent = norm(f.agent)
  if (camada === 'secrets' || agent.includes('secrets')) return 'secret'
  if (camada === 'deps' || agent.includes('dependencies')) return 'deps'
  if (camada === 'compliance' || camada === 'lgpd' || agent.includes('compliance')) return 'lgpd'
  if (camada === 'code' || camada === 'sast' || agent.includes('semgrep') || agent.includes('stack')) return 'sast'
  return camada || 'other'
}

export function matchCatalog(findings, catalogItems) {
  const items = catalogItems.map((it) => {
    const sig = it.signal ? new RegExp(it.signal, 'i') : null
    const hit = findings.find((f) => {
      const loc = locFromText(f)
      // (a) caminho localizável → exige arquivo + linha (quando houver linha)
      if (loc.file) {
        if (!fileMatch(loc.file, it.file)) return false
        if (loc.line == null) return true // nível-arquivo
        return Math.abs(loc.line - it.line) <= LINE_TOL
      }
      // (b) sem localização → credita via SINAL semântico tool-agnóstico (finding repo-level).
      //     Sem sinal definido, não credita (evita creditar findings ubíquos como "criptografia").
      if (sig) return sig.test(`${f.title || ''} ${f.evidence || ''}`)
      return false
    })
    return {
      ...it,
      detected: !!hit,
      by: hit?.id ?? null,
      categoryAgree: hit ? oracleCategory(hit) === it.category : false,
    }
  })
  return {
    total: items.length,
    detected: items.filter((i) => i.detected).length,
    items,
  }
}

export { oracleCategory }
