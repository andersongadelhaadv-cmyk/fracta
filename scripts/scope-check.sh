#!/usr/bin/env bash
# scope-check.sh [HASH_BASE] — exit 1 se qualquer arquivo alterado estiver fora de .claude/zona-verde,
# se testes existentes foram alterados/removidos, se houve deleção, ou se há segredo/dado pessoal no diff.
# Usado pelo Stop hook, pelo pre-commit e pela CI. Não edite via agente.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
BASE="${1:-}"; [ "$BASE" = "sem-git" ] && BASE=""
ALLOW=".claude/zona-verde"; VIOL=0
if [ ! -s "$ALLOW" ] || ! grep -qvE '^\s*(#|$)' "$ALLOW"; then echo "FALHA: $ALLOW vazio — nenhuma alteração é permitida"; VIOL=1; fi

CHANGED=$( { git diff --name-only ${BASE:+"$BASE"}; git diff --cached --name-only; git ls-files --others --exclude-standard; } 2>/dev/null | grep -vx '.claude/zona-verde' | sort -u )
shopt -s globstar extglob nullglob
while IFS= read -r f; do
  [ -z "$f" ] && continue; ok=0
  while IFS= read -r pat; do
    pat="${pat%%#*}"; pat="$(echo "$pat" | xargs)"; [ -z "$pat" ] && continue
    case "$pat" in */) pat="${pat}**";; esac
    # shellcheck disable=SC2053
    [[ "$f" == $pat ]] && { ok=1; break; }
  done < "$ALLOW"
  [ $ok -eq 0 ] && { echo "FORA DA ZONA VERDE: $f"; VIOL=1; }
done <<< "$CHANGED"

LINES=$(git diff ${BASE:+"$BASE"} --numstat 2>/dev/null | awk '{s+=$1+$2} END{print s+0}')
[ "$LINES" -gt "${MAX_DIFF_LINES:-150}" ] && echo "AVISO: diff acumulado com $LINES linhas (> ${MAX_DIFF_LINES:-150}). Justifique no relatório." && [ "${STRICT_DIFF_SIZE:-0}" = "1" ] && VIOL=1

for f in $(git diff ${BASE:+"$BASE"} --name-only --diff-filter=MD 2>/dev/null | grep -E '(\.test\.|\.spec\.|__tests__/|/tests?/|_test\.(py|go)$|\.snap$|conftest\.py)' || true); do
  removed=$(git diff ${BASE:+"$BASE"} --numstat -- "$f" | awk '{print $2}')
  if [ "${removed:-0}" -gt 0 ] && [ "${ALLOW_TEST_EDIT:-0}" != "1" ]; then
    echo "BLOQUEADO: '$f' altera/remove $removed linha(s) de teste existente. Só o humano libera (ALLOW_TEST_EDIT=1 após revisar)."; VIOL=1
  fi
done

if git diff ${BASE:+"$BASE"} --name-only --diff-filter=D 2>/dev/null | grep -q .; then
  echo "BLOQUEADO: deleção de arquivo(s): $(git diff ${BASE:+"$BASE"} --name-only --diff-filter=D | tr '\n' ' '). Reporte como obsoleto; não remova."; VIOL=1
fi

# Segredos e dados pessoais nas linhas adicionadas
if git diff ${BASE:+"$BASE"} -- . ':(exclude)docs/protocolo' ':(exclude).claude' ':(exclude)scripts/scope-check.sh' ':(exclude)*/CLAUDE.md' ':(exclude)CLAUDE.md' 2>/dev/null | grep -E '^\+[^+]' | grep -Eq '(\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b|\b[0-9]{7}-[0-9]{2}\.[0-9]{4}\.[0-9]\.[0-9]{2}\.[0-9]{4}\b|\bsk-[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY|(password|passwd|senha|secret|token|api[_-]?key)\s*[:=]\s*["'"'"'][^"'"'"']{6,}|://[^/\s:]+:[^/\s@]+@)'; then
  echo "BLOQUEADO: possível segredo ou dado pessoal (CPF, nº CNJ, chave, senha) nas linhas adicionadas. Remova antes de entregar."; VIOL=1
fi

if command -v gitleaks >/dev/null 2>&1; then gitleaks protect --staged --no-banner -q 2>/dev/null || { echo "BLOQUEADO: gitleaks encontrou segredo."; VIOL=1; }; fi

[ $VIOL -eq 0 ] && echo "SCOPE OK ($(echo "$CHANGED" | grep -c .) arquivo(s) alterado(s), $LINES linhas desde ${BASE:-HEAD})"
exit $VIOL
