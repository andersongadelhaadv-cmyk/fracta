import type { Target } from './types.js'

/**
 * Valida que um Target é utilizável ANTES de rodar qualquer agente. Erra cedo
 * com mensagem clara — nunca deixa um campo trocado virar crash cru + veredito
 * verde enganoso (#26). Um target é utilizável se tiver:
 *  - uma `url` http(s) válida (para os agentes DAST/vivos), OU
 *  - um `repoPath` (para os agentes SAST/repo-only).
 *
 * O caso clássico: `targets.yaml` com `baseUrl:` em vez de `url:` — `url` vem
 * `undefined` e os 4 agentes que instanciam o HTTP client crashavam com
 * "Cannot read properties of undefined (reading 'replace')" sob um "✅ PASSOU".
 */
export function assertUsableTarget(target: Target): void {
  const name = target?.name ?? '(sem nome)'
  const url = target?.url
  const repoPath = target?.repoPath

  const hasRepo = typeof repoPath === 'string' && repoPath.trim().length > 0

  if (url === undefined || url === null || (typeof url === 'string' && url.trim() === '')) {
    if (hasRepo) return // target somente-repo (SAST) é válido sem url
    throw new Error(
      `Target "${name}" não tem \`url\` nem \`repoPath\`. Defina uma \`url\` http(s) ` +
      `(o campo canônico é \`url:\`, não \`baseUrl:\`) ou um \`repoPath\` para auditoria de repositório.`,
    )
  }

  if (!/^https?:\/\//i.test(url)) {
    if (hasRepo) return // repo-only com url malformada: os agentes de url pulam honestamente
    throw new Error(
      `Target "${name}" tem uma \`url\` inválida ("${url}"): precisa começar com http:// ou https://.`,
    )
  }
}
