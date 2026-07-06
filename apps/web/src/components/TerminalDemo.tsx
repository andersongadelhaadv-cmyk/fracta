/**
 * Demo animada (SVG inline, self-contained → passa no CSP; sem JS).
 * Conteúdo = OUTPUT REAL de `npx fractascan verify https://fracta.pro` (capturado
 * em 06/07/2026). Honestidade: só o efeito de revelação é cosmético; as linhas são
 * exatamente o que o comando imprime. Respeita `prefers-reduced-motion`.
 */
const CSS = `
.td-l{opacity:0}
.td-1{animation:td1 15s infinite}
.td-2{animation:td2 15s infinite}
.td-3{animation:td3 15s infinite}
.td-4{animation:td4 15s infinite}
@keyframes td1{0%,3%{opacity:0}6%,88%{opacity:1}94%,100%{opacity:0}}
@keyframes td2{0%,20%{opacity:0}24%,88%{opacity:1}94%,100%{opacity:0}}
@keyframes td3{0%,34%{opacity:0}38%,88%{opacity:1}94%,100%{opacity:0}}
@keyframes td4{0%,46%{opacity:0}50%,88%{opacity:1}94%,100%{opacity:0}}
.td-cur{animation:tdblink 1.1s steps(1) infinite}
@keyframes tdblink{0%,50%{opacity:1}51%,100%{opacity:0}}
@media (prefers-reduced-motion:reduce){.td-l{opacity:1}.td-1,.td-2,.td-3,.td-4{animation:none}.td-cur{opacity:1;animation:none}}
`

export function TerminalDemo() {
  return (
    <svg
      viewBox="0 0 720 236"
      role="img"
      aria-label="Terminal: npx fractascan verify https://fracta.pro — nenhum tracker disparou antes do consentimento"
      className="w-full max-w-2xl"
      xmlns="http://www.w3.org/2000/svg"
    >
      <style dangerouslySetInnerHTML={{ __html: CSS }} />
      <rect x="1" y="1" width="718" height="234" rx="10" fill="#0b0d10" stroke="#1e2531" />
      {/* barra de título */}
      <circle cx="26" cy="24" r="5" fill="#2b3340" />
      <circle cx="46" cy="24" r="5" fill="#2b3340" />
      <circle cx="66" cy="24" r="5" fill="#2b3340" />
      <text x="360" y="28" textAnchor="middle" fontFamily="ui-monospace, Menlo, monospace" fontSize="12" fill="#5b6472">fracta — terminal</text>
      <line x1="1" y1="44" x2="719" y2="44" stroke="#1e2531" />
      {/* linhas (output real) */}
      <g fontFamily="ui-monospace, 'SFMono-Regular', Menlo, monospace" fontSize="14">
        <text className="td-l td-1" x="24" y="82" fill="#d1d5db">
          <tspan fill="#5eead4">$</tspan> npx fractascan verify https://fracta.pro
        </text>
        <text className="td-l td-2" x="24" y="116" fill="#8b93a1">Verificação em runtime de https://fracta.pro/</text>
        <text className="td-l td-3" x="24" y="148" fill="#d1d5db">
          <tspan fill="#34d399">✓</tspan> nenhum tracker disparou antes do consentimento
        </text>
        <text className="td-l td-4" x="24" y="180" fill="#8b93a1">CMP: não detectado</text>
        {/* prompt final + cursor piscando */}
        <text x="24" y="214" fill="#5eead4">$</text>
        <rect className="td-cur" x="40" y="202" width="9" height="16" fill="#5eead4" />
      </g>
    </svg>
  )
}
