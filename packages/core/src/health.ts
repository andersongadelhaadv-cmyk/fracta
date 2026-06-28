import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { connect } from 'node:net'
import type { Target, TargetHealth, TargetHealthStatus } from './types.js'

/**
 * Verificação de saúde do alvo ANTES de auditar (Lacuna 1 do guia). Um alvo fora
 * do ar ou um repo inexistente nunca pode ser interpretado como "tudo seguro".
 * Tudo é read-only e tolerante a falha — qualquer erro vira "não respondeu".
 */
export async function checkTargetHealth(target: Target): Promise<TargetHealth> {
  const hasRepo = !!target.repoPath
  const repoAccessible = hasRepo ? await isGitRepo(target.repoPath as string) : true

  const stagingApplicable = isHttpUrl(target.url)
  const stagingResponding = stagingApplicable ? await httpResponds(target.url) : undefined

  const host = target.infra?.host
  const vpsApplicable = !!host
  const vpsReachable = host ? await tcpReachable(host) : undefined

  const status = deriveHealthStatus({
    hasRepo,
    repoAccessible,
    stagingApplicable,
    stagingResponding,
    vpsApplicable,
    vpsReachable,
  })

  return { repoAccessible, stagingResponding, vpsReachable, status }
}

export interface HealthInputs {
  hasRepo: boolean
  repoAccessible: boolean
  stagingApplicable: boolean
  stagingResponding?: boolean
  vpsApplicable: boolean
  vpsReachable?: boolean
}

/**
 * Deriva o status agregado (lógica pura, testável). Repo obrigatório inacessível
 * é fatal (`unreachable` → o orquestrador aborta). Para os probes externos opcionais:
 * todos de pé = healthy; alguns = degraded; nenhum = unreachable.
 */
export function deriveHealthStatus(p: HealthInputs): TargetHealthStatus {
  if (p.hasRepo && !p.repoAccessible) return 'unreachable'

  const probes: boolean[] = []
  if (p.stagingApplicable) probes.push(p.stagingResponding === true)
  if (p.vpsApplicable) probes.push(p.vpsReachable === true)

  if (probes.length === 0) return 'healthy' // nada externo a checar (ex.: repo-only)
  if (probes.every(Boolean)) return 'healthy'
  if (probes.some(Boolean)) return 'degraded'
  return 'unreachable'
}

function isHttpUrl(url: string | undefined): boolean {
  return !!url && /^https?:\/\//i.test(url)
}

async function isGitRepo(repoPath: string): Promise<boolean> {
  try {
    const dir = await stat(repoPath)
    if (!dir.isDirectory()) return false
    // .git pode ser diretório (repo normal) ou arquivo (worktree/submodule).
    await stat(join(repoPath, '.git'))
    return true
  } catch {
    return false
  }
}

async function httpResponds(url: string, timeoutMs = 5_000): Promise<boolean> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    // Qualquer resposta HTTP (incl. 4xx/5xx) significa "de pé". fetch só rejeita
    // em falha de rede/timeout.
    await fetch(url, { method: 'HEAD', signal: controller.signal })
    return true
  } catch {
    return false
  } finally {
    clearTimeout(timer)
  }
}

function tcpReachable(host: string, port = 22, timeoutMs = 4_000): Promise<boolean> {
  return new Promise(resolve => {
    const socket = connect({ host, port })
    let settled = false
    const finish = (value: boolean): void => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(value)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true))
    socket.once('timeout', () => finish(false))
    socket.once('error', (err: NodeJS.ErrnoException) => {
      // ECONNREFUSED = host respondeu (porta fechada) → host está alcançável.
      finish(err.code === 'ECONNREFUSED')
    })
  })
}
