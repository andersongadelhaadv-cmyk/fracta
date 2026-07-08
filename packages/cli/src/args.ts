import { parseArgs } from 'util'

/**
 * Opções da CLI, isoladas aqui para serem testáveis sem spawnar o processo.
 * `version` é NOVA: `--version`/`-V` é convenção universal e antes vazava um
 * `TypeError [ERR_PARSE_ARGS_UNKNOWN_OPTION]` cru (com um `}` solto do dump).
 */
export const CLI_OPTIONS = {
  target: { type: 'string', short: 't' },
  config: { type: 'string', short: 'c', default: './configs/targets.yaml' },
  depth: { type: 'string', short: 'd', default: 'full' },
  output: { type: 'string', short: 'o', default: './fracta-reports' },
  state: { type: 'string', default: './fracta-state.db' },
  'no-state': { type: 'boolean', default: false },
  llm: { type: 'boolean', default: false },
  'no-llm': { type: 'boolean', default: false },
  'fail-on': { type: 'string', default: 'critical,high' },
  'docs-path': { type: 'string', default: './' },
  force: { type: 'boolean', default: false },
  verbose: { type: 'boolean', short: 'v', default: false },
  version: { type: 'boolean', short: 'V', default: false },
  help: { type: 'boolean', short: 'h', default: false },
} as const

/**
 * Erro de USO (opção desconhecida / valor mal formado): mensagem honesta e legível,
 * não o throw cru do Node. `main()` a captura e sai com exit(1) + orientação.
 */
export class CliUsageError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CliUsageError'
  }
}

type ParsedArgs = ReturnType<typeof parseArgs<{
  options: typeof CLI_OPTIONS
  args: string[]
  allowPositionals: true
}>>

/**
 * Envelopa `parseArgs` para NUNCA vazar o erro interno do Node. Uma flag inválida
 * vira `CliUsageError` com o nome da opção + dica de `--help`, em vez do
 * `TypeError [ERR_PARSE_ARGS_UNKNOWN_OPTION]` seguido de um `}` solto.
 */
export function parseCliArgs(argv: string[]): ParsedArgs {
  try {
    return parseArgs({
      args: argv,
      allowPositionals: true,
      options: CLI_OPTIONS,
    })
  } catch (e) {
    const err = e as NodeJS.ErrnoException
    if (typeof err.code === 'string' && err.code.startsWith('ERR_PARSE_ARGS')) {
      // Extrai a opção citada ('--flagX') da mensagem do Node, sem repassar o dump cru.
      const opt = err.message.match(/'(-[^']+)'/)?.[1] ?? '(opção inválida)'
      throw new CliUsageError(
        `[Fracta] Opção desconhecida: ${opt}. Rode "fracta --help" para ver as opções válidas.`,
      )
    }
    throw e
  }
}
