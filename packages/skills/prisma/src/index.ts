import { randomUUID } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'

const STUDIO_PATHS = ['/prisma', '/prisma-studio', '/_prisma', '/admin/prisma', '/studio']

const TRIGGER_PATHS = [
  '/api/users', '/api/auth/register', '/api/auth/signup',
  '/api/clientes', '/api/usuarios',
]

const PRISMA_LEAK_PATTERNS: RegExp[] = [
  /\bPrismaClient(?:KnownRequestError|ValidationError|UnknownRequestError)\b/,
  /\bP\d{4}\b/,
  /Unique constraint failed/i,
  /Foreign key constraint failed/i,
  /Invalid `prisma\./i,
  /at\s+\/[\w/.-]+\/@prisma\/client/,
]

function findLeak(body: string): RegExp | null {
  for (const re of PRISMA_LEAK_PATTERNS) {
    if (re.test(body)) return re
  }
  return null
}

export class PrismaSkill implements SecurityAgent {
  name = 'Prisma Skill'
  category: AgentCategory = 'security'
  concurrency = 2
  timeoutMs = 60_000

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target } = scope

    if (!target.stack.includes('prisma')) return findings

    const client = new FractaHttpClient(target.url)
    const ignore = target.ignore ?? []

    await this.probeStudio(scope, client, findings, ignore)
    await this.probeErrorLeak(scope, client, findings, ignore)

    return findings
  }

  private async probeStudio(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    for (const path of STUDIO_PATHS) {
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await client.request(path, { timeoutMs: 4_000 })
        if (res.status === 200 && /prisma\s+studio/i.test(res.raw.substring(0, 4000))) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'critical',
            title: `Prisma Studio exposto: ${path}`,
            description: `${path} parece servir o Prisma Studio publicamente. Studio dá acesso CRUD irrestrito ao banco — qualquer pessoa pode ler/editar/deletar dados.`,
            endpoint: path,
            evidence: `GET ${path} → HTTP 200 (${res.raw.length} bytes — body contém "Prisma Studio")`,
            recommendation: 'Nunca exponha o Studio em produção. Rode local via `npx prisma studio` e bloqueie qualquer proxy/ingress nessa rota.',
            references: ['https://www.prisma.io/docs/orm/tools/prisma-studio'],
            createdAt: new Date(),
          })
          return
        }
      } catch { /* ignora */ }
    }
  }

  private async probeErrorLeak(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    const bogusBody = {
      email: 'fracta-test@example.com',
      password: 'fracta-test-9999',
      ___fracta_trigger__: { nested: { deep: 'value' } },
    }

    for (const path of TRIGGER_PATHS) {
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await client.request(path, {
          method: 'POST',
          body: bogusBody,
          timeoutMs: 5_000,
        })

        if (res.status === 404) continue

        const leak = findLeak(res.raw)
        if (leak) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'medium',
            title: `Erro Prisma vazado em resposta: ${path}`,
            description: `POST em ${path} retornou corpo com padrão Prisma (${leak.source}). Vazar nomes de model/coluna ou códigos como P2002 ajuda atacantes a mapear o schema do banco.`,
            endpoint: path,
            evidence: `POST ${path} → HTTP ${res.status}\n${res.raw.substring(0, 300).replace(/\s+/g, ' ').trim()}`,
            recommendation: 'Sempre traduza erros do Prisma para respostas opacas em produção:\n```typescript\ntry {\n  await prisma.user.create({ data });\n} catch (e) {\n  if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === \'P2002\') {\n    throw new ConflictException(\'Recurso já existe\');\n  }\n  throw new InternalServerErrorException();\n}\n```',
            references: [
              'https://www.prisma.io/docs/orm/reference/error-reference',
              'https://owasp.org/www-community/Improper_Error_Handling',
            ],
            createdAt: new Date(),
          })
          return
        }
      } catch { /* ignora */ }
    }
  }
}
