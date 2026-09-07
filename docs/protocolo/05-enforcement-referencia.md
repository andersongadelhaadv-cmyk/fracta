> **Nota:** este arquivo é a referência conceitual da Camada 5. A implementação real e testada está em `.claude/hooks/`, `.claude/settings.json`, `scripts/scope-check.sh`, `.githooks/pre-commit` e `.github/workflows/scope-check.yml` deste repositório, instalados pelo kit — e os nomes reais dos hooks são `guard-zona-verde.sh`, `guard-bash.sh`, `session-start.sh`, `after-edit.sh`, `stop-check.sh`. Em divergência, valem os arquivos instalados. Para verificar o enforcement (E1) sem esbarrar no guard, use `sed -n "/\[core\]/,/^\[/p" .git/config` em vez de `git config core.hooksPath`; a Zona Verde vive em `.claude/zona-verde` (local, ignorado pelo git) e na CI vem das labels `zona:<glob>` do PR.

# CAMADA 5 — ENFORCEMENT MECÂNICO (instalado por humano, uma vez por repositório)

Este protocolo não confia na memória nem na boa vontade do agente. Confia em hooks, allowlists e CI. O texto é a última linha de defesa, não a única. O agente **verifica** que os controles existem (passo E1) e **nunca os edita**.

**E1 — Verificar no início de cada sessão** (colar saída literal):
```
ls -la .claude/settings.json .claude/hooks/ scripts/scope-check.sh .githooks/pre-commit 2>&1
git config core.hooksPath
cat .claude/zona-verde 2>&1
git rev-parse HEAD; git branch --show-current
```
Se faltar algo, reporte ao humano e trabalhe em modo PROPOR até ser instalado.

**E2 — Zona Verde é um arquivo, não uma frase.** `.claude/zona-verde` (um glob por linha) é escrito **só pelo humano, no editor dele**. O agente pede: "Confirme a Zona Verde criando/ajustando `.claude/zona-verde` com: ...". Autorização de fronteira = humano acrescenta o caminho no arquivo (ou aplica label `zona:<glob>` no PR). Enquanto o arquivo não cobrir o caminho, o hook bloqueia — isso é o comportamento esperado, não um erro a contornar. Fail-closed: sem arquivo, nada edita.

**E3 — Isolamento:** `git worktree add -b <tipo>/<slug> ../wt-<slug> main`. Nunca commit nem push em `main`. O ambiente onde o agente roda **não tem** chave SSH da VPS, `.env` de produção nem token de deploy. Deploy só por CI após merge humano.

**E4 — `.claude/settings.json` (Claude Code):**
```json
{
  "permissions": {
    "deny": [
      "Read(./.env)", "Read(./.env.*)", "Read(./**/secrets/**)", "Read(./**/*.pem)", "Read(./**/*.key)",
      "Edit(./.env*)", "Edit(./package.json)", "Edit(./package-lock.json)", "Edit(./pnpm-lock.yaml)", "Edit(./yarn.lock)",
      "Edit(./requirements*.txt)", "Edit(./poetry.lock)", "Edit(./Dockerfile*)", "Edit(./docker-compose*)",
      "Edit(./nginx/**)", "Edit(./.github/**)", "Edit(./**/migrations/**)", "Edit(./prisma/schema.prisma)",
      "Edit(./scripts/deploy*)", "Edit(./scripts/scope-check.sh)", "Edit(./.claude/**)", "Edit(./.githooks/**)",
      "Bash(npm install *)", "Bash(npm i *)", "Bash(pnpm add *)", "Bash(yarn add *)", "Bash(pip install *)", "Bash(npx *)",
      "Bash(git push --force*)", "Bash(git push -f*)", "Bash(git reset --hard*)", "Bash(git clean*)", "Bash(rm -rf *)",
      "Bash(git commit --no-verify*)", "Bash(chmod *)", "Bash(ssh *)", "Bash(scp *)", "Bash(psql *)", "Bash(mysql *)",
      "Bash(pm2 *)", "Bash(systemctl *)", "Bash(docker *)"
    ],
    "allow": [
      "Bash(npm test*)", "Bash(npm run lint*)", "Bash(npm run build*)", "Bash(npm run typecheck*)",
      "Bash(git status*)", "Bash(git diff*)", "Bash(git log*)", "Bash(git blame*)", "Bash(git show*)",
      "Bash(git rev-parse*)", "Bash(git branch --show-current*)", "Bash(rg *)", "Bash(grep *)", "Bash(ls *)", "Bash(cat *)"
    ]
  },
  "hooks": {
    "SessionStart": [{ "hooks": [{ "type": "command", "command": "mkdir -p .claude/run && (npm test --silent > .claude/run/baseline-tests.log 2>&1; echo exit=$? >> .claude/run/baseline-tests.log); git rev-parse HEAD > .claude/run/hash-inicial; echo 'Baseline e hash inicial gravados em .claude/run/'" }] }],
    "PreToolUse": [
      { "matcher": "Edit|Write|MultiEdit|NotebookEdit", "hooks": [{ "type": "command", "command": "bash .claude/hooks/guard-zona-verde.sh" }] },
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "bash .claude/hooks/guard-bash.sh" }] }
    ],
    "PostToolUse": [
      { "matcher": "Edit|Write|MultiEdit", "hooks": [{ "type": "command", "command": "bash .claude/hooks/test-after-edit.sh" }] }
    ],
    "Stop": [{ "hooks": [{ "type": "command", "command": "bash scripts/scope-check.sh $(cat .claude/run/hash-inicial) || { echo 'Entrega bloqueada: reverta o excedente ou peça fronteira.' >&2; exit 2; }" }] }]
  }
}
```

**E5 — `.claude/hooks/guard-zona-verde.sh`** (exit 2 = bloqueia e devolve o motivo ao agente):
```bash
#!/usr/bin/env bash
set -euo pipefail
INPUT=$(cat); FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
[ -z "$FILE" ] && exit 0
ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd); REL=$(realpath -m --relative-to="$ROOT" "$FILE"); ALLOW="$ROOT/.claude/zona-verde"
[ -s "$ALLOW" ] || { echo "BLOQUEADO: .claude/zona-verde ausente/vazio. Publique o MAPA DE ZONAS e peça ao humano para preenchê-lo." >&2; exit 2; }
case "$REL" in
  .env*|*.env|package.json|*lock*|requirements*.txt|Dockerfile*|docker-compose*|nginx*|.github/*|.gitlab-ci*|*/migrations/*|prisma/schema.prisma|.claude/*|.githooks/*|scripts/deploy*|scripts/scope-check.sh|*/auth/*|*/guards/*|*/policies/*|*/middleware/auth*)
    echo "BLOQUEADO: '$REL' é Zona Vermelha estrutural. Emita PEDIDO DE AUTORIZAÇÃO DE FRONTEIRA." >&2; exit 2 ;;
esac
shopt -s globstar extglob nullglob
while IFS= read -r pat; do [[ -z "$pat" || "$pat" == \#* ]] && continue; [[ "$REL" == $pat ]] && exit 0; done < "$ALLOW"
echo "BLOQUEADO: '$REL' fora da Zona Verde ($(grep -v '^#' "$ALLOW" | tr '\n' ' ')). Emita PEDIDO DE AUTORIZAÇÃO DE FRONTEIRA e aguarde." >&2; exit 2
```

**E6 — `.claude/hooks/guard-bash.sh`:**
```bash
#!/usr/bin/env bash
set -euo pipefail
CMD=$(cat | jq -r '.tool_input.command // empty'); [ -z "$CMD" ] && exit 0
if echo "$CMD" | grep -Eq '(rm -rf|git (push[^|]*(--force|-f)|reset --hard|clean|checkout (--|\.)|restore \.|branch -D)|drop (table|database)|truncate|flushall|--no-verify|chmod|systemctl|pm2|docker (rm|kill|system prune)|migrate:(reset|fresh)|prisma migrate (reset|deploy)|curl[^|]*\| *(ba)?sh)'; then
  echo "BLOQUEADO: comando destrutivo/irreversível ou que desativa controles. Peça autorização explícita ao humano NESTE momento." >&2; exit 2; fi
if echo "$CMD" | grep -Eq '(sed -i|>{1,2} *[^&]|tee |mv |cp |rsync |touch |mkdir )'; then
  echo "BLOQUEADO: escrita via Bash. Use Edit/Write (auditados pelo hook de Zona Verde)." >&2; exit 2; fi
if echo "$CMD" | grep -Eq '(cat|less|head|tail|grep|rg)[^|]*(\.env|\.pem|\.key|credentials)'; then
  echo "BLOQUEADO: leitura de secret. Use grep -c NOME .env para verificar existência." >&2; exit 2; fi
exit 0
```

**E7 — `scripts/scope-check.sh`** (Stop hook, pre-commit e CI):
```bash
#!/usr/bin/env bash
# scope-check.sh <HASH_INICIAL> — exit 1 se qualquer arquivo alterado estiver fora de .claude/zona-verde
set -euo pipefail; cd "$(git rev-parse --show-toplevel)"; BASE="${1:-}"; ALLOW=".claude/zona-verde"
[ -s "$ALLOW" ] || { echo "FALHA: $ALLOW ausente/vazio"; exit 1; }
CHANGED=$( { git diff --name-only ${BASE:+$BASE}; git diff --cached --name-only; git ls-files --others --exclude-standard; } | sort -u )
shopt -s globstar extglob; VIOL=0
while IFS= read -r f; do [ -z "$f" ] && continue; ok=0
  while IFS= read -r pat; do [[ -z "$pat" || "$pat" == \#* ]] && continue; [[ "$f" == $pat ]] && { ok=1; break; }; done < "$ALLOW"
  [ $ok -eq 0 ] && { echo "FORA DA ZONA VERDE: $f"; VIOL=1; }
done <<< "$CHANGED"
LINES=$(git diff ${BASE:+$BASE} --numstat | awk '{s+=$1+$2} END{print s+0}')
[ "$LINES" -gt "${MAX_DIFF_LINES:-150}" ] && echo "AVISO: diff acumulado com $LINES linhas (> ${MAX_DIFF_LINES:-150}). Justifique."
# testes existentes: só adições
for f in $(git diff ${BASE:+$BASE} --name-only --diff-filter=MD | grep -E '(\.test\.|\.spec\.|__tests__/|/tests?/|_test\.py|\.snap$)' || true); do
  removed=$(git diff ${BASE:+$BASE} --numstat -- "$f" | awk '{print $2}'); [ "${removed:-0}" -gt 0 ] && [ "${ALLOW_TEST_EDIT:-0}" != "1" ] && { echo "BLOQUEADO: '$f' altera/remove $removed linha(s) de teste existente (humano: ALLOW_TEST_EDIT=1)"; VIOL=1; }
done
git diff ${BASE:+$BASE} --name-only --diff-filter=D | grep -q . && { echo "BLOQUEADO: deleção de arquivo. Reporte como obsoleto; não remova."; VIOL=1; }
# segredos e PII no diff
git diff ${BASE:+$BASE} | grep -E '^\+' | grep -Eq '(\b[0-9]{3}\.?[0-9]{3}\.?[0-9]{3}-?[0-9]{2}\b|[0-9]{7}-[0-9]{2}\.[0-9]{4}\.[0-9]\.[0-9]{2}\.[0-9]{4}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{20,}|-----BEGIN|password=|token=|://[^/]+:[^/]+@)' && { echo "BLOQUEADO: possível segredo ou dado pessoal no diff."; VIOL=1; }
[ $VIOL -eq 0 ] && echo "SCOPE OK ($(echo "$CHANGED" | grep -c .) arquivo(s), $LINES linhas)"; exit $VIOL
```

**E8 — `.githooks/pre-commit`** (`git config core.hooksPath .githooks`): `bash scripts/scope-check.sh "$(cat .claude/run/hash-inicial 2>/dev/null)"`. Como `--no-verify` está na deny list, não se pula.

**E9 — CI e proteção de branch:** workflow `scope-check` em todo PR que resolve o allowlist a partir do **branch base** ou de label `zona:<glob>` aplicada por humano (nunca do próprio PR), roda `scope-check.sh origin/<base>` e a suíte; branch protection em `main` exigindo PR, ≥ 1 aprovação humana, status checks `scope-check` + `tests`, sem force push, sem commit direto. CODEOWNERS cobrindo `.env*`, `package.json`, lockfiles, `prisma/`, `**/migrations/`, `.github/`, `Dockerfile`, `nginx/`, `scripts/deploy*`, `src/shared/`, `**/auth/`, `.claude/`. Snapshot de OpenAPI (`git diff --exit-code openapi.json`) como status check para mudanças de contrato HTTP.

**E10 — `CLAUDE.md` hierárquico:** um por pasta vermelha (`src/shared/CLAUDE.md`: "ZONA VERMELHA ESTRUTURAL. Somente leitura. Consumidores: `rg -l <símbolo>`"; `**/migrations/CLAUDE.md`: "Migrations proibidas sem fronteira; expand/contract"; `.github/CLAUDE.md`: "Se um check falhar, o problema é no código, não no check") — o aviso chega no momento da leitura, não só no início da sessão.

**E11 — Medição:** cada bloqueio de hook grava em `.claude/run/blocked.log`. Se o agente bate 5× na mesma parede, o escopo está errado ou o prompt está mal calibrado — sinal para o humano intervir, não para afrouxar o hook.

---
