/**
 * `fractascan init` — scaffold de um `targets.yaml` inicial, bem-comentado.
 * Destrava as tools intrusivas (a maior fricção do onboarding). Idempotente:
 * recusa sobrescrever sem `--force`. Sem dep nova (não-interativo).
 */

/** Template starter — 1 alvo de exemplo, comentado. SEM alvos reais. */
export const TARGETS_TEMPLATE = `# Fracta — targets.yaml
# Declare aqui os sistemas que VOCÊ controla e autoriza a testar.
# É este arquivo que libera os testes intrusivos (auth, IDOR): eles só rodam
# contra o que estiver declarado abaixo.
#
# ⚠️  NUNCA aponte para produção com dados reais. Use staging.
# Variáveis de ambiente: use \${NOME_DA_VAR} (nunca commite senha em texto puro).

targets:
  meu-saas:
    url: https://staging.meuapp.com.br
    # Stack ajuda os agentes a darem o fix EXATO (ex.: snippet de next.config.js).
    stack: [nextjs, prisma]

    # (opcional) Autenticação — necessária para os testes de auth/IDOR.
    auth:
      type: jwt
      endpoint: /api/auth/login
      credentials:
        email: test@meuapp.com.br
        password: "\${MEUAPP_TEST_PASS}"   # defina no ambiente, não aqui

    # Quais agentes rodar neste alvo.
    agents:
      - HEADERS Agent
      - AUTH Agent
      - IDOR Agent
      - DOCS Agent

    # Rotas a ignorar (ruído/ops).
    ignore:
      - /api/health
      - /api/metrics

    # (opcional) Auditoria do REPO local (read-only): dependências, secrets, docs.
    # repoPath: ../meu-saas
`

export interface InitDeps {
  /** true se o arquivo já existe. */
  exists(path: string): Promise<boolean>
  /** escreve o conteúdo (criando dirs pai). */
  write(path: string, content: string): Promise<void>
}

export interface InitResult {
  ok: boolean
  wrote: boolean
  message: string
}

export async function runInit(opts: { path: string; force: boolean }, deps: InitDeps): Promise<InitResult> {
  if ((await deps.exists(opts.path)) && !opts.force) {
    return {
      ok: false,
      wrote: false,
      message: `${opts.path} já existe. Use \`fractascan init --force\` para sobrescrever (isso apaga o conteúdo atual).`,
    }
  }
  await deps.write(opts.path, TARGETS_TEMPLATE)
  return {
    ok: true,
    wrote: true,
    message: `✓ ${opts.path} criado. Edite-o com os seus alvos e rode: fractascan scan`,
  }
}
