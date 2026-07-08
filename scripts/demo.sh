#!/usr/bin/env bash
# Fracta — demo à prova de falha para apresentações.
#
# Cria um mini-SaaS DELIBERADAMENTE vulnerável, roda o Fracta nele e mostra:
#   1) veredito FALHOU com achados HIGH (SQL injection, CORS wildcard, chave hardcoded)
#   2) camada semântica do semgrep (se instalado) — SAST dataflow, não só regex
#   3) scorecard OWASP Top 10 (postura por categoria)
#   4) SARIF 2.1.0 (pronto p/ GitHub Code Scanning)
#   5) verify-csp: cobertura de CSP em RUNTIME no fracta.pro
#
# Uso:  bash scripts/demo.sh
# Silencioso p/ conversão: FRACTA_NO_PROMO já é setado aqui.
# Semgrep é lento no Windows → este script PRÉ-AQUECE as regras p/ não travar ao vivo.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$ROOT/packages/cli/dist/index.js"
# Path node-friendly: no Windows/git-bash o node nativo NÃO entende `/tmp/...`.
# cygpath -m dá `C:/...` (que bash e node leem); no Linux/Mac usa o path como está.
WORK_RAW="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/fracta-demo-$$")"
if command -v cygpath >/dev/null 2>&1; then WORK="$(cygpath -m "$WORK_RAW")"; else WORK="$WORK_RAW"; fi
export FRACTA_NO_PROMO=1
# Semgrep no Windows tem startup lento (pysemgrep). Bound curto p/ demo previsível:
# se demorar, degrada p/ skip em ~20s. Em Linux/CI o core rápido roda em segundos.
export FRACTA_SEMGREP_TIMEOUT="${FRACTA_SEMGREP_TIMEOUT:-20}"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

# 0) CLI buildado?
if [ ! -f "$CLI" ]; then
  say "Buildando o CLI (primeira vez)"
  (cd "$ROOT" && npx turbo run build --filter=fractascan >/dev/null 2>&1) || { echo "build falhou"; exit 1; }
fi

# 1) Mini-SaaS vulnerável. A chave falsa é MONTADA de fragmentos p/ o gitleaks NÃO
#    flagar ESTE script (o valor só existe, contíguo, no arquivo gerado — de propósito).
mkdir -p "$WORK/src"
FAKE_KEY="sk""_live_""51DEMOfakefakefakefake000000"
cat > "$WORK/src/pagamentos.ts" <<EOF
import Stripe from 'stripe'
const stripe = new Stripe('${FAKE_KEY}')                 // chave hardcoded (CWE-798)
export async function cobrar(userId: string, prisma: any) {
  return prisma.\$queryRawUnsafe('SELECT * FROM cards WHERE user = ' + userId)  // SQL injection (CWE-89)
}
EOF
cat > "$WORK/src/server.ts" <<'EOF'
import express from 'express'
import { exec } from 'child_process'
const app = express()
app.use((req, res, next) => { res.header('Access-Control-Allow-Origin', '*'); next() })  // CORS wildcard (CWE-942)
app.get('/diag', (req, res) => exec('nslookup ' + req.query.host, (e, o) => res.send(o)))  // command injection
app.listen(3000)
EOF
cat > "$WORK/package.json" <<'EOF'
{ "name": "loja-demo", "version": "1.0.0", "dependencies": { "express": "^4.18.0", "@prisma/client": "^5.0.0" } }
EOF
# Agentes rápidos e determinísticos por padrão. Semgrep (SAST semântico) é lento no
# Windows → opt-in via DEMO_WITH_SEMGREP=1 (ideal em Linux/CI, onde roda em segundos).
AGENTS="      - STACK Agent
      - SECRETS Agent
      - COMPLIANCE Agent
      - DOCS Agent"
if [ "${DEMO_WITH_SEMGREP:-}" = "1" ]; then AGENTS="$AGENTS
      - SEMGREP Agent"; fi
cat > "$WORK/targets.yaml" <<EOF
targets:
  demo:
    repoPath: "$WORK"
    agents:
$AGENTS
EOF
(cd "$WORK" && git init -q && git add -A && git -c user.email=demo@x -c user.name=demo commit -qm init) 2>/dev/null

# 2) Pré-aquece o semgrep só quando ligado (senão nem entra no scan).
if [ "${DEMO_WITH_SEMGREP:-}" = "1" ] && command -v semgrep >/dev/null 2>&1; then
  say "Pré-aquecendo o semgrep (cacheia regras — máx 30s)"
  timeout 30 semgrep scan --config p/security-audit --metrics=off --quiet "$WORK/src" >/dev/null 2>&1 || true
fi

# 3) O scan (FALHA de propósito — achou vulns reais). --no-state = determinístico.
say "fracta scan — auditando o mini-SaaS vulnerável"
node "$CLI" scan --target demo --config "$WORK/targets.yaml" --no-state \
  --fail-on critical,high --output "$WORK/reports" || true

# 4) Scorecard OWASP + trecho do relatório
MD="$(ls -t "$WORK/reports"/*.md 2>/dev/null | head -1)"
if [ -n "${MD:-}" ]; then
  say "Scorecard OWASP Top 10 (postura por categoria)"
  # imprime da seção do scorecard até o PRÓXIMO cabeçalho (##), robusto.
  awk '/## .*Postura por OWASP/{p=1;print;next} p&&/^## /{exit} p{print}' "$MD"
  say "SARIF gerado (upload no GitHub Code Scanning)"
  ls -1 "$WORK/reports"/*.sarif 2>/dev/null | head -1
fi

# 5) verify-csp em runtime (precisa de Chrome/Chromium). Degrada com nota se ausente.
say "fracta verify-csp — cobertura de CSP em RUNTIME (browser real) no fracta.pro"
node "$CLI" verify-csp https://fracta.pro || \
  echo "(verify-csp precisa de Chromium: 'npx playwright install chromium' — pulei)"

say "Fim do demo — relatórios em $WORK/reports"
