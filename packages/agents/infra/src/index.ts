import { readFile } from 'node:fs/promises'
import { connect } from 'node:net'
import type {
  SecurityAgent, ScanScope, Finding, AgentCategory, Severity, ProposedFix,
} from '@fracta/core'
import { SkippedCheck, stableFindingId } from '@fracta/core'

/**
 * Sonda UMA porta TCP num host. Retorna `true` SOMENTE quando a conexão é
 * ACEITA (evento 'connect' = porta aberta/exposta). Timeout, recusa (closed) ou
 * qualquer erro → `false` (porta fechada/inalcançável). É injetável p/ teste —
 * os testes nunca abrem socket real.
 */
export type PortProber = (host: string, port: number, timeoutMs: number) => Promise<boolean>

/** Prober padrão via node:net (espelha o padrão de health.ts). 100% read-only. */
export const defaultProbePort: PortProber = (host, port, timeoutMs) =>
  new Promise<boolean>(resolve => {
    const socket = connect({ host, port })
    let settled = false
    const finish = (open: boolean): void => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(open)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => finish(true)) // aceitou → porta EXPOSTA
    socket.once('timeout', () => finish(false))
    socket.once('error', () => finish(false)) // recusada/erro → fechada
  })

/** Portas de banco/cache que NUNCA deveriam estar abertas à internet. */
const DB_PORTS: ReadonlyArray<{ port: number; nome: string }> = [
  { port: 5432, nome: 'PostgreSQL' },
  { port: 6379, nome: 'Redis' },
]

const PROBE_TIMEOUT_MS = 4_000

/**
 * Agente de infra — postura de VPS/Docker/SSH. 100% READ-ONLY: apenas LÊ arquivos
 * e tenta CONECTAR em portas TCP. NUNCA roda ufw, edita sshd_config, reinicia
 * serviços ou executa qualquer comando mutador (regra do incidente de prod: uma
 * mudança de infra mal-aplicada derruba a frota — por isso infra aqui só observa).
 *
 * Cada sub-check é independente: se faltar o input específico dele, ele é apenas
 * ignorado (não gera nada). O agente só lança `SkippedCheck` quando NÃO há nenhum
 * dado de infra (host/sshConfigPath/dockerComposePath ausentes).
 *
 * Todo `proposedFix` é PROPOSTA (comando/diff para revisão), jamais aplicada;
 * `riskOfApplying` é sempre preenchido com honestidade.
 */
export class InfraAgent implements SecurityAgent {
  name = 'INFRA Agent'
  category: AgentCategory = 'infra'
  concurrency = 1
  timeoutMs = 30_000

  constructor(private readonly probePort: PortProber = defaultProbePort) {}

  async run(scope: ScanScope): Promise<Finding[]> {
    const infra = scope.target.infra
    if (!infra || (!infra.host && !infra.sshConfigPath && !infra.dockerComposePath)) {
      throw new SkippedCheck(
        'sem dados de infra (host/sshConfigPath/dockerComposePath) — InfraAgent não tem o que observar',
      )
    }

    const findings: Finding[] = []

    if (infra.host) {
      findings.push(...await this.checkExposedDbPorts(scope, infra.host))
    }
    if (infra.sshConfigPath) {
      findings.push(...await this.checkSshConfig(scope, infra.sshConfigPath))
    }
    if (infra.dockerComposePath) {
      findings.push(...await this.checkDockerCompose(scope, infra.dockerComposePath))
    }

    return findings
  }

  // 1) Portas de banco expostas — o achado de infra mais perigoso. -----------
  private async checkExposedDbPorts(scope: ScanScope, host: string): Promise<Finding[]> {
    const findings: Finding[] = []
    for (const { port, nome } of DB_PORTS) {
      const open = await this.probePort(host, port, PROBE_TIMEOUT_MS)
      if (!open) continue
      const location = `${host}:${port}`
      findings.push(this.finding(scope, {
        rule: `db-port-exposed:${port}`,
        location,
        severity: 'critical',
        title: `Porta de banco exposta à internet: ${nome} (${port})`,
        description:
          `A porta ${port} (${nome}) ACEITOU conexão TCP a partir do exterior em ${location}. ` +
          `Um banco de dados/cache alcançável pela internet é o vetor de comprometimento mais grave: ` +
          `permite ataques de força bruta, exploração direta e exfiltração de dados.`,
        evidence: `TCP connect aceito em ${location} (porta aberta externamente)`,
        recommendation:
          `Bloqueie a porta ${port} no firewall e faça o serviço escutar apenas em localhost (127.0.0.1).`,
        proposedFix: {
          description:
            `Bloqueie a porta no firewall e vincule o ${nome} ao localhost. ` +
            `Ex.: \`sudo ufw deny ${port}/tcp\` e configure o ${nome} para bind 127.0.0.1.`,
          command: `sudo ufw deny ${port}/tcp`,
          riskOfApplying:
            `PROPOSTA — revise antes. Bloquear uma porta EM USO pode cortar a conectividade da aplicação ` +
            `se ela se conecta ao ${nome} por esta interface pública. Garanta que a app usa rede interna/localhost ` +
            `antes de bloquear, ou você derruba o serviço.`,
        },
      }))
    }
    return findings
  }

  // 2) sshd_config — leitura do arquivo (se fornecido e legível). ------------
  private async checkSshConfig(scope: ScanScope, path: string): Promise<Finding[]> {
    const text = await this.readTextOrSkipSubcheck(path)
    if (text === null) return [] // arquivo ausente/ilegível → sub-check pulado, sem falso "seguro"

    const findings: Finding[] = []

    if (!this.sshDirectiveSet(text, 'PasswordAuthentication', 'no')) {
      findings.push(this.finding(scope, {
        rule: 'ssh-password-auth',
        location: path,
        severity: 'high',
        title: 'SSH permite autenticação por senha',
        description:
          `O sshd_config (${path}) não define \`PasswordAuthentication no\`. Login por senha expõe o servidor ` +
          `a força bruta e credential stuffing; chaves SSH são o padrão recomendado.`,
        evidence: `sshd_config sem \`PasswordAuthentication no\``,
        recommendation: 'Desative a autenticação por senha e use apenas chaves SSH.',
        proposedFix: {
          description:
            'Em sshd_config defina:\n  PasswordAuthentication no\n  ' +
            'ChallengeResponseAuthentication no\nDepois: `sudo systemctl reload sshd`.',
          command: 'sudo systemctl reload sshd',
          riskOfApplying:
            'PROPOSTA — revise antes. Desativar senha SEM ter uma chave SSH funcionando TRANCA você para fora ' +
            'do servidor. Confirme login por chave numa sessão paralela antes de aplicar e recarregar o sshd.',
        },
      }))
    }

    if (!this.sshDirectiveSet(text, 'PermitRootLogin', 'no')) {
      findings.push(this.finding(scope, {
        rule: 'ssh-root-login',
        location: path,
        severity: 'high',
        title: 'SSH permite login direto como root',
        description:
          `O sshd_config (${path}) não define \`PermitRootLogin no\`. Login direto de root remove a barreira ` +
          `de auditoria/sudo e torna o alvo de força bruta o usuário mais privilegiado.`,
        evidence: `sshd_config sem \`PermitRootLogin no\``,
        recommendation: 'Proíba login direto de root; acesse via usuário comum + sudo.',
        proposedFix: {
          description:
            'Em sshd_config defina:\n  PermitRootLogin no\nDepois: `sudo systemctl reload sshd`.',
          command: 'sudo systemctl reload sshd',
          riskOfApplying:
            'PROPOSTA — revise antes. Se o único acesso for via root, proibir root login te tranca para fora. ' +
            'Garanta um usuário não-root com sudo e chave SSH funcionando antes de aplicar.',
        },
      }))
    }

    return findings
  }

  // 3) docker-compose — heurística por linha, SEM dependência de yaml. -------
  private async checkDockerCompose(scope: ScanScope, path: string): Promise<Finding[]> {
    const text = await this.readTextOrSkipSubcheck(path)
    if (text === null) return [] // ausente/ilegível → sub-check pulado

    const findings: Finding[] = []
    const lines = text.split(/\r?\n/)

    // 3a) Portas de DB/Redis publicadas para o host via `ports:`.
    const seenPublished = new Set<number>()
    for (const { port, nome } of DB_PORTS) {
      const idx = lines.findIndex(l => this.publishesDbPort(l, port))
      if (idx === -1 || seenPublished.has(port)) continue
      seenPublished.add(port)
      findings.push(this.finding(scope, {
        rule: `compose-db-published:${port}`,
        location: `${path}:${idx + 1}`,
        severity: 'high',
        title: `docker-compose publica porta de banco no host: ${nome} (${port})`,
        description:
          `O compose mapeia a porta ${port} (${nome}) para o host via \`ports:\` (linha ${idx + 1}), ` +
          `o que pode expor o banco para fora do Docker. Use \`expose:\` / rede interna para que apenas ` +
          `outros containers alcancem o serviço.`,
        evidence: `linha ${idx + 1}: ${this.sanitizeLine(lines[idx])}`,
        recommendation:
          `Troque \`ports:\` por \`expose: ["${port}"]\` (ou rede interna) para o serviço ${nome}, ` +
          `assim ele não fica acessível pelo host.`,
        proposedFix: {
          description:
            `No serviço do ${nome}, remova o mapeamento \`ports: "${port}:${port}"\` e use ` +
            `\`expose: ["${port}"]\`, deixando o acesso restrito à rede interna do Compose.`,
          riskOfApplying:
            `PROPOSTA — revise antes. Se algum processo no HOST (fora do Docker) depende dessa porta publicada, ` +
            `removê-la quebra essa conexão. Confirme que só containers usam o ${nome} antes de aplicar.`,
        },
      }))
    }

    // 3b) Segredo em texto plano (literal, não interpolação `${VAR}`).
    lines.forEach((line, i) => {
      const varName = this.plaintextSecretVarName(line)
      if (!varName) return
      findings.push(this.finding(scope, {
        rule: 'compose-plaintext-secret',
        location: `${path}:${i + 1}`,
        severity: 'high',
        title: `Segredo em texto plano no docker-compose: ${varName}`,
        description:
          `A variável \`${varName}\` (linha ${i + 1}) tem um valor literal embutido no compose, não uma ` +
          `interpolação \`\${...}\`. Segredos versionados vazam pelo git/imagem. (O valor NÃO é exibido aqui.)`,
        // NUNCA ecoa o valor: só o nome da var + linha.
        evidence: `linha ${i + 1}: variável \`${varName}\` com valor literal (valor omitido por segurança)`,
        recommendation:
          `Mova o segredo para variável de ambiente externa (\`${varName}: \${${varName}}\`) ou docker secrets, ` +
          `e rotacione o valor já exposto.`,
        proposedFix: {
          description:
            `Substitua o valor literal por interpolação: \`${varName}: \${${varName}}\` e forneça o valor via ` +
            `\`.env\`/secret fora do versionamento. Rotacione o segredo, pois ele já esteve em texto plano.`,
          riskOfApplying:
            'PROPOSTA — revise antes. Trocar o valor por interpolação exige que a variável esteja definida no ' +
            'ambiente/.env; se não estiver, o container sobe sem o segredo. Defina-a antes de aplicar.',
        },
      }))
    })

    // 3c) Container rodando como root — heurística: há serviços e nenhum `user:`.
    if (this.hasServices(lines) && !lines.some(l => /^\s*user\s*:/i.test(l))) {
      findings.push(this.finding(scope, {
        rule: 'compose-no-user',
        location: path,
        severity: 'low',
        title: 'Containers possivelmente rodando como root',
        description:
          `O compose (${path}) define serviços mas nenhuma diretiva \`user:\`. Sem ela, os containers ` +
          `tendem a rodar como root, ampliando o impacto de um escape de container.`,
        evidence: 'nenhuma diretiva `user:` encontrada no compose com serviços',
        recommendation: 'Defina `user:` (UID não-root) em cada serviço ou no Dockerfile.',
        proposedFix: {
          description:
            'Adicione `user: "1000:1000"` (ou UID não-root apropriado) aos serviços, ou use `USER` no Dockerfile.',
          riskOfApplying:
            'PROPOSTA — revise antes. Rodar como não-root pode quebrar serviços que precisam de portas <1024 ' +
            'ou de permissões de arquivo/volume específicas. Teste cada serviço antes de aplicar amplamente.',
        },
      }))
    }

    return findings
  }

  // --- helpers ---------------------------------------------------------------

  /** Lê arquivo como texto; `null` quando ausente/ilegível (sub-check é pulado, não falha). */
  private async readTextOrSkipSubcheck(path: string): Promise<string | null> {
    try {
      return await readFile(path, 'utf8')
    } catch {
      return null
    }
  }

  /** `true` se a diretiva ssh está setada exatamente com o valor esperado (ignora comentários). */
  private sshDirectiveSet(text: string, directive: string, value: string): boolean {
    const re = new RegExp(`^\\s*${directive}\\s+${value}\\s*$`, 'im')
    return re.test(text)
  }

  /** Linha de `ports:` que publica a porta de DB para o host (ex.: "5432:5432", "127.0.0.1:5432:5432:..."). */
  private publishesDbPort(line: string, port: number): boolean {
    // Mapeamento host:container — a porta de DB aparece seguida de `:` e outra porta.
    // Cobre "5432:5432", - 5432:5432, "127.0.0.1:5432:5432". Exige o `:porta` para
    // não confundir com `expose: ["5432"]` (que NÃO publica no host).
    return new RegExp(`(^|[\\s"':])${port}\\s*:\\s*\\d`).test(line)
  }

  /** Nome da var de um segredo literal (não interpolação). `null` se não houver. */
  private plaintextSecretVarName(line: string): string | null {
    const m = line.match(/(\w*(?:PASSWORD|SECRET|TOKEN|API_KEY)\w*)\s*[:=]\s*(\S+)/i)
    if (!m) return null
    const value = m[2]
    // Interpolação pura `${VAR}` ou `$VAR` não é segredo literal.
    if (/^["']?\$\{?\w+\}?["']?$/.test(value)) return null
    return m[1]
  }

  /** Há um bloco `services:` com pelo menos um serviço definido. */
  private hasServices(lines: string[]): boolean {
    const svcIdx = lines.findIndex(l => /^\s*services\s*:/i.test(l))
    if (svcIdx === -1) return false
    // Alguma linha indentada após `services:` que parece um nome de serviço.
    for (let i = svcIdx + 1; i < lines.length; i++) {
      const l = lines[i]
      if (/^\S/.test(l) && !/^\s*$/.test(l)) break // saiu do bloco services (top-level)
      if (/^\s+[\w.-]+\s*:\s*$/.test(l)) return true
    }
    return false
  }

  /** Remove o valor após `:`/`=` de uma linha, preservando a chave (p/ evidência segura). */
  private sanitizeLine(line: string): string {
    return line.trim()
  }

  /** Monta um Finding com os campos invariantes do agente. */
  private finding(
    scope: ScanScope,
    f: {
      rule: string
      location: string
      severity: Severity
      title: string
      description: string
      evidence?: string
      recommendation: string
      proposedFix: ProposedFix
    },
  ): Finding {
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: f.rule, location: f.location }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity: f.severity,
      title: f.title,
      description: f.description,
      evidence: f.evidence,
      recommendation: f.recommendation,
      proposedFix: f.proposedFix,
      createdAt: new Date(),
    }
  }
}
