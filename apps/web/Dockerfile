# syntax=docker/dockerfile:1
# Build do monorepo Fracta → app web Next.js standalone. Build acontece no GitHub
# Actions (a VPS NUNCA builda). Node 22-slim porque o motor usa node:sqlite (>=22.5).

FROM node:22-slim AS builder
WORKDIR /app
RUN corepack enable
# Copia o monorepo inteiro (lockfile + workspaces) e instala com lockfile travado.
COPY . .
RUN pnpm install --frozen-lockfile
# Build topológico: deps de workspace (web-scan/core/agent-headers) + Next standalone.
RUN pnpm --filter "@fracta/web..." build

FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3850
ENV HOSTNAME=0.0.0.0
ENV FRACTA_WEB_DB=/data/fracta-web.db
RUN useradd -m -u 1001 nextjs \
  && mkdir -p /data \
  && chown -R nextjs:nextjs /data

# Saída standalone do Next (com outputFileTracingRoot na raiz do monorepo, o layout
# espelha o repo: ./apps/web/server.js + ./node_modules + ./packages).
COPY --from=builder --chown=nextjs:nextjs /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /app/apps/web/.next/static ./apps/web/.next/static
# Estáticos servidos de public/ (og.png, ícones PWA) — standalone NÃO inclui sozinho.
COPY --from=builder --chown=nextjs:nextjs /app/apps/web/public ./apps/web/public

USER nextjs
EXPOSE 3850
VOLUME /data
CMD ["node", "apps/web/server.js"]
