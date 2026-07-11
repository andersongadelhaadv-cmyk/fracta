# Imagem de bench ISOLADA: builda o Fracta e roda o batch. O código dos repos-alvo NUNCA é
# executado (scan 100% estático) — a isolação é sobre não rodar código de 3os, não sobre no-network.
#
# Nota honesta de rede: o clone e o `npm audit` (recall de deps) precisam de rede. Com rede
# cortada, os agentes de deps/secrets(hist) reportam `skipped` (honestidade), não falso-limpo.
FROM node:24-slim

# git p/ clonar; nada de toolchains de build dos alvos (não instalamos deps deles).
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# semgrep é opcional no crosscheck; a imagem base do Fracta já traz o pack embarcado.
WORKDIR /app
COPY . /app
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build

# Usuário não-root: o batch escreve só em /app/bench/results (montado como volume).
USER node
ENTRYPOINT ["node", "bench/runner/run-batch.mjs"]
CMD ["--concurrency", "4", "--timeout-ms", "600000"]
