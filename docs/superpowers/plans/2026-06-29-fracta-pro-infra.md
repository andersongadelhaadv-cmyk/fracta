# Fracta.pro — Infra & Deploy (Plano 3)

> **For agentic workers:** padrão da frota = build no GitHub Actions → imagem no GHCR → VPS só faz pull + restart. A VPS **nunca** builda Docker. Ver skill `padroniza-cicd`.

**Goal:** Colocar `apps/web` em produção em `https://fracta.pro` — Dockerfile Next standalone, CI no Actions publicando no GHCR, VPS faz pull+restart, nginx com server block dedicado + Let's Encrypt, e **endurecer o `default_server`→444** (corrige a causa-raiz: hoje `fracta.pro` cai no default e serve a home do ADVOCUS com erro de CORS).

**Architecture:** container Next standalone escutando **3850** (porta livre, ver [[infra-vps-deploy]]) em `127.0.0.1`; nginx proxy_pass `fracta.pro`/`www.fracta.pro` → `127.0.0.1:3850` com TLS; volume p/ persistir `fracta-web.db`. Imagem multi-stage (build no Actions, runtime mínimo).

---

## Task 1: Dockerfile (Next standalone) + .dockerignore

**Files:** criar `apps/web/Dockerfile`, `apps/web/.dockerignore`.

- [ ] **Step 1: `Dockerfile`** multi-stage, **buildando o monorepo** (o web depende de `@fracta/web-scan`/core/agent-headers):
  - `base`: `node:22-slim` (≥22.5 p/ node:sqlite), `corepack enable`.
  - `deps`: copia `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `package.json` raiz + todos os `packages/*/package.json` + `apps/web/package.json`; `pnpm install --frozen-lockfile`.
  - `build`: copia o repo; `pnpm --filter @fracta/web... build` (constrói deps workspace + Next). `output: standalone` gera `apps/web/.next/standalone`.
  - `runner`: `node:22-slim`, `USER node`, copia `.next/standalone` + `.next/static` + `public`; `ENV NODE_ENV=production PORT=3850 FRACTA_WEB_DB=/data/fracta-web.db`; `EXPOSE 3850`; `CMD ["node","apps/web/server.js"]`. Cria `/data` (volume).
- [ ] **Step 2: `.dockerignore`** — `node_modules`, `.next`, `**/dist` (rebuilda), `*.db`, `.git`, `fracta-reports`, `configs/targets.local.yaml`.
- [ ] **Step 3:** validar build local: `docker build -f apps/web/Dockerfile -t fracta-web:test .` (na máquina dev, NÃO na VPS). Subir e cur-lar `localhost:3850`.
- [ ] **Step 4: Commit** `feat(web): Dockerfile Next standalone (monorepo build)`.

---

## Task 2: GitHub Actions → GHCR

**Files:** criar `.github/workflows/deploy-web.yml`.

- [ ] **Step 1:** workflow disparado em push na `master` que toque `apps/web/**`, `packages/**`, ou o próprio workflow (e `workflow_dispatch`):
  - job `build-push`: checkout → login GHCR (`GITHUB_TOKEN`) → `docker/build-push-action` → tag `ghcr.io/andersongadelhaadv-cmyk/fracta-web:latest` + `:${{ github.sha }}`. (Não usar PAT — `GITHUB_TOKEN` efêmero, padrão da frota.)
  - job `deploy` (needs build-push): SSH na VPS (`VPS_SSH_KEY*` secret existente) → `docker pull` da imagem → `docker compose -f /opt/apps/fracta-web/docker-compose.yml up -d` (pull+restart, **sem build**) → healthcheck `curl -fsS http://127.0.0.1:3850` com retry → rollback p/ tag anterior se falhar.
- [ ] **Step 2:** garantir que o CI existente (gitleaks/test) continua verde; este é um workflow adicional.
- [ ] **Step 3: Commit** `ci(web): build→GHCR→VPS pull (padrão da frota)`.

---

## Task 3: VPS — compose + volume + porta (read-only setup, sem buildar)

**Files (na VPS):** `/opt/apps/fracta-web/docker-compose.yml`, volume `/opt/apps/fracta-web/data`.

- [ ] **Step 1:** `ssh hostinger`; criar `/opt/apps/fracta-web/`. `docker-compose.yml`: serviço `web` → `image: ghcr.io/.../fracta-web:latest`, `ports: "127.0.0.1:3850:3850"` (só loopback; nginx faz o TLS), `volumes: ./data:/data`, `restart: unless-stopped`, `pull_policy: always`. Login GHCR read (`GITHUB_TOKEN` de deploy / token read:packages existente — NÃO o PAT revogado).
- [ ] **Step 2:** confirmar 3850 livre (`ss -ltnp | grep 3850` vazio). 
- [ ] **Step 3:** `docker compose pull && up -d`; `curl 127.0.0.1:3850` responde. (Primeira imagem pode vir do primeiro run do Actions.)

---

## Task 4: nginx — server block fracta.pro + Let's Encrypt + default_server 444

**Files (na VPS):** `/etc/nginx/sites-available/fracta.pro` (+ symlink em sites-enabled); ajuste no bloco `default_server`.

- [ ] **Step 1: DIAGNÓSTICO (read-only) antes de mudar nada** — `nginx -T` p/ achar o atual `default_server` e confirmar que `fracta.pro` cai nele; `grep -rl 'default_server' /etc/nginx/sites-enabled/`; `ls -la /etc/nginx/sites-enabled/`. Backup de cada arquivo tocado (`*.bak.fractapro.$(date +%s)`).
- [ ] **Step 2: server block `fracta.pro`** (`server_name fracta.pro www.fracta.pro;`): `proxy_pass http://127.0.0.1:3850;` com headers `X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto` (o app lê o IP real); `proxy_set_header Host $host`. Primeiro só `:80` p/ o desafio ACME.
- [ ] **Step 3: cert Let's Encrypt** — `certbot --nginx -d fracta.pro -d www.fracta.pro` (certbot já instalado na VPS pelos outros vhosts). Confirma 443 + redirect 80→443.
- [ ] **Step 4: ENDURECER o `default_server`** — no bloco default (catch-all), `return 444;` para host não reconhecido em :80 e :443 (com um cert self-signed/snakeoil no 443 default p/ não vazar outro vhost). Isto corrige o vazamento ADVOCUS e qualquer domínio solto futuro. **Cuidado c-rúrgico:** não tocar nos `server_name` legítimos dos outros 50+ apps; só o bloco catch-all. `nginx -t` antes de cada `reload`.
- [ ] **Step 5:** `nginx -t && systemctl reload nginx`.

---

## Task 5: Verificação de produção (read-only/smoke)

- [ ] **Step 1:** `curl -I https://fracta.pro` → 200, servindo a **home do Fracta** (não ADVOCUS); TLS válido (`openssl s_client` / cert do Let's Encrypt).
- [ ] **Step 2:** `curl -I https://fracta.pro -H 'Host: dominio-inexistente.xyz'`... na verdade testar o default: `curl -sI http://76.13.170.79 -H 'Host: lixo.invalido'` → conexão fechada (444).
- [ ] **Step 3:** fluxo e2e: scan de `example.com` via UI → nota A–F → `/r/[shareId]` carrega → badge SVG → e-mail capturado. **Nenhum check finge verde.**
- [ ] **Step 4:** `qa-frota fracta full` read-only contra produção (home + scan benigno).
- [ ] **Step 5:** o próprio Fracta CLI escaneia `https://fracta.pro` (dogfood) → deve passar nos headers que ele exige (HSTS etc. setados no `next.config`).

---

## Notas de segurança/operação
- Segredos via ambiente/secrets do Actions; **nada commitado** (gitleaks no CI tem que ficar verde).
- VPS **nunca builda** Docker; só pull. Não tocar em outros apps além do vhost novo + o catch-all default.
- DB `fracta-web.db` em volume `/data` — sobrevive a redeploy. Backup é YAGNI por ora (dado é cache + e-mails; e-mails valem backup simples futuro).
- Porta 3850 só em `127.0.0.1` (nginx termina TLS). Sem exposição direta.
