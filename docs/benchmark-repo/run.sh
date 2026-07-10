#!/usr/bin/env bash
# Reprodução one-command do benchmark (docs/benchmark.md).
#   bash run.sh <dir-de-trabalho>
# Planta o repo, roda gitleaks/semgrep/trivy/npm-audit/fracta e imprime a tabela de recall.
# Ferramentas ausentes são puladas (entram como 0). Requer: node. Opcional: gitleaks, semgrep,
# trivy (ou docker), e o Fracta buildado (packages/mcp-server) para a coluna do Fracta.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${1:?uso: bash run.sh <dir-de-trabalho>}"
REPO="$WORK/repo"; OUT="$WORK/out"; mkdir -p "$OUT"

echo "→ plantando repo em $REPO"
rm -rf "$REPO"; node "$HERE/plant.mjs" "$REPO" >/dev/null
( cd "$REPO" && git init -q && git config user.email b@l && git config user.name b && git add -A && git -c commit.gpgsign=false commit -qm plant )

run() { echo "→ $1" >&2; shift; "$@"; }  # log em stderr: não polui o JSON redirecionado p/ stdout

if command -v gitleaks >/dev/null 2>&1; then
  run "gitleaks" gitleaks detect --source "$REPO" --no-banner --report-format json --report-path "$OUT/gitleaks.json" >/dev/null 2>&1 || true
fi
if command -v semgrep >/dev/null 2>&1; then
  run "semgrep p/security-audit" semgrep scan --config p/security-audit --json --quiet --metrics=off --timeout 20 "$REPO" > "$OUT/semgrep.json" 2>/dev/null || true
fi
if command -v trivy >/dev/null 2>&1; then
  run "trivy" trivy fs --scanners vuln --quiet --format json "$REPO" > "$OUT/trivy.json" 2>/dev/null || true
elif command -v docker >/dev/null 2>&1; then
  run "trivy (docker)" docker run --rm -v "$REPO":/r aquasec/trivy:latest fs --scanners vuln --quiet --format json /r > "$OUT/trivy.json" 2>/dev/null || true
fi
run "npm audit" bash -c "cd '$REPO' && npm i --package-lock-only --no-audit --no-fund >/dev/null 2>&1; npm audit --json > '$OUT/npmaudit.json' 2>/dev/null" || true

# Fracta: usa o dist buildado do monorepo, se presente (via um mini-harness).
if [ -f "$HERE/../../packages/mcp-server/package.json" ]; then
  run "fracta" node "$HERE/fracta-run.mjs" "$REPO" > "$OUT/fracta.json" 2>/dev/null || true
fi

echo ""
node "$HERE/score.mjs" --truth "$HERE/ground-truth.json" \
  --gitleaks "$OUT/gitleaks.json" --semgrep "$OUT/semgrep.json" --trivy "$OUT/trivy.json" \
  --npmaudit "$OUT/npmaudit.json" --fracta "$OUT/fracta.json" --json "$OUT/scoreboard.json"
