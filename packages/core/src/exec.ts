import { spawn } from 'node:child_process'

export interface CommandResult {
  stdout: string
  stderr: string
  code: number | null
}

export interface RunCommandOptions {
  cwd?: string
  timeoutMs?: number
  /** Texto a enviar no stdin do processo (ex.: para ferramentas que leem stdin). */
  input?: string
}

export type CommandRunner = (
  command: string,
  args: string[],
  opts?: RunCommandOptions,
) => Promise<CommandResult>

/**
 * Executa um comando externo de forma read-only e captura stdout/stderr.
 * Compartilhado pelos agentes baseados em repositório (npm audit, gitleaks...).
 * Rejeita com ENOENT se o binário não existe (o agente decide skip vs error) e
 * com erro de timeout se estourar o prazo. Nunca usa a saída para escrever nada.
 */
export const runCommand: CommandRunner = (command, args, opts = {}) => {
  return new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: opts.cwd,
      // No Windows, npm/gitleaks são .cmd e exigem shell para resolver no PATH.
      shell: process.platform === 'win32',
    })

    let stdout = ''
    let stderr = ''
    let timer: NodeJS.Timeout | undefined

    if (opts.timeoutMs) {
      timer = setTimeout(() => {
        child.kill('SIGKILL')
        reject(new Error(`timeout após ${opts.timeoutMs}ms ao executar: ${command}`))
      }, opts.timeoutMs)
    }

    child.stdout.on('data', d => { stdout += d.toString() })
    child.stderr.on('data', d => { stderr += d.toString() })
    child.on('error', err => {
      if (timer) clearTimeout(timer)
      reject(err)
    })
    child.on('close', code => {
      if (timer) clearTimeout(timer)
      resolve({ stdout, stderr, code })
    })

    if (opts.input !== undefined) {
      child.stdin.write(opts.input)
      child.stdin.end()
    }
  })
}
