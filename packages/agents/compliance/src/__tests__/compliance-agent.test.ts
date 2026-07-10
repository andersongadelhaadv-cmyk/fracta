import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ComplianceAgent } from '../index.js'
import { SkippedCheck } from '@fracta/core'
import type { ScanScope } from '@fracta/core'

let repoDir: string

function scopeFor(repoPath?: string): ScanScope {
  return {
    target: { name: 'DemoSaaS', url: 'file://local', stack: ['nestjs'], repoPath },
    depth: 'full',
    agents: ['COMPLIANCE Agent'],
    runId: 'run-1',
    startedAt: new Date(),
  }
}

describe('ComplianceAgent', () => {
  beforeEach(async () => {
    repoDir = await mkdtemp(join(tmpdir(), 'fracta-compliance-'))
  })
  afterEach(async () => {
    await rm(repoDir, { recursive: true, force: true })
  })

  it('skips when there is no repoPath', async () => {
    await expect(new ComplianceAgent().run(scopeFor(undefined)))
      .rejects.toBeInstanceOf(SkippedCheck)
  })

  it('flags sensitive data in a log WITHOUT echoing the logged value', async () => {
    const code = 'export function f(user: any) {\n  console.log(`cpf=${user.cpf}`)\n}\n'
    await writeFile(join(repoDir, 'svc.ts'), code)

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const hit = findings.find(f => f.title.startsWith('Possível dado sensível em log'))
    expect(hit).toBeDefined()
    expect(hit!.severity).toBe('high')
    expect(hit!.camada).toBe('compliance')

    // SANITIZAÇÃO: evidence só tem arquivo:linha + termo, nunca o valor logado.
    expect(hit!.evidence).toContain('svc.ts:2')
    expect(hit!.evidence).toContain('cpf')
    // O valor logado (`user.cpf`) NÃO pode aparecer em lugar nenhum do finding.
    expect(hit!.evidence).not.toContain('user.cpf')
    expect(hit!.evidence).not.toContain('${')
    expect(hit!.description).not.toContain('user.cpf')

    // rule key determinística e id estável.
    const a = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(a.find(f => f.title.startsWith('Possível dado sensível em log'))!.id).toBe(hit!.id)

    // proposedFix sempre com riskOfApplying honesto.
    expect(hit!.proposedFix).toBeDefined()
    expect(hit!.proposedFix!.riskOfApplying).toBeTruthy()
  })

  // ---- Precisão do "dado sensível em log": VALOR logado, não prosa da mensagem (FPs reais do zap-api) ----
  it('NÃO flagga termo sensível que está SÓ na mensagem estática (valores logados são seguros)', async () => {
    // Casos reais do zap-api: o termo ("token"/"cartão"/"password") está no TEXTO da mensagem,
    // enquanto os valores logados são { ip }, { ids } — nada sensível.
    await writeFile(
      join(repoDir, 'log-fp.ts'),
      [
        'logger.warn({ ip: req.ip }, "[Diagnostic] sem header X-Diagnostic-Token")',
        'logger.warn("Reset password rate limit exceeded", { count })',
        'logger.info({ zapInstanceDbId, stripeSubscriptionId }, "[ZapStripe] Cartão adicionado em trial")',
        'console.log(`  → senha resetada, lockout limpo, conta ativa`)',
      ].join('\n'),
    )
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings.filter(f => f.title.startsWith('Possível dado sensível em log'))).toHaveLength(0)
  })

  it('NÃO flagga console.log dentro de STRING/COMENTÁRIO (conteúdo de blog/docs, não logging real)', async () => {
    await writeFile(
      join(repoDir, 'content.ts'),
      [
        'const code = "console.log(user.processo)"           // exemplo em string, não é log real',
        'console.log(data) // { instance, token }             // token está no comentário',
        'app.listen(3000, () => console.log("API on")); const x = "fala de cartão aqui"',
      ].join('\n'),
    )
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings.filter(f => f.title.startsWith('Possível dado sensível em log'))).toHaveLength(0)
  })

  it('AINDA flagga quando o VALOR logado é sensível: ${password}, cpf=${user.cpf}, token=${t} (recall)', async () => {
    await writeFile(
      join(repoDir, 'log-tp.ts'),
      [
        'console.log(`Senha:  ${password}`)',       // valor interpolado é a senha
        'logger.info(`cpf=${user.cpf}`)',           // identificador sensível na interpolação
        'logger.debug(`token=${t}`)',               // rótulo colado à interpolação
      ].join('\n'),
    )
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const logs = findings.filter(f => f.title.startsWith('Possível dado sensível em log'))
    expect(logs.length).toBe(3) // os três são TP e devem continuar sendo pegos
  })

  it('flags password storage without a hashing lib', async () => {
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { '@prisma/client': '^5' } }),
    )
    await writeFile(
      join(repoDir, 'auth.ts'),
      'export async function register(p: string) {\n  return prisma.user.create({ data: { password: p } })\n}\n',
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const hit = findings.find(f => f.title === 'Possível armazenamento de senha sem hashing')
    expect(hit).toBeDefined()
    expect(hit!.severity).toBe('high')
    expect(hit!.proposedFix!.riskOfApplying).toContain('CONFIRMAÇÃO HUMANA')
  })

  it('NÃO flagga senha-sem-hashing em MONOREPO: bcrypt num package.json de subpasta (backend/) — FP real do zap-api', async () => {
    await mkdir(join(repoDir, 'backend'), { recursive: true })
    await writeFile(join(repoDir, 'package.json'), JSON.stringify({ name: 'root', workspaces: ['backend'] }))
    await writeFile(join(repoDir, 'backend', 'package.json'), JSON.stringify({ name: 'backend', dependencies: { bcrypt: '^5' } }))
    await writeFile(
      join(repoDir, 'backend', 'auth.ts'),
      'export async function register(p: string) {\n  return prisma.user.create({ data: { password: p } })\n}\n',
    )
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    // o hashing existe no monorepo (backend/) → não é vazamento; ler só a raiz gerava FP
    expect(findings.find(f => f.title === 'Possível armazenamento de senha sem hashing')).toBeUndefined()
  })

  it('does NOT flag password storage when bcrypt is present', async () => {
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { bcrypt: '^5' } }),
    )
    await writeFile(
      join(repoDir, 'auth.ts'),
      'export async function register(p: string) {\n  return prisma.user.create({ data: { password: p } })\n}\n',
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings.find(f => f.title === 'Possível armazenamento de senha sem hashing')).toBeUndefined()
  })

  it('flags tenant-isolation in a sensitive file and encryption-unclear, with deterministic rule keys', async () => {
    // arquivo sensível com findMany sem escopo de tenant e sem TLS no repo
    await writeFile(
      join(repoDir, 'repo.ts'),
      'export function list() {\n  // processo de cliente\n  return prisma.processo.findMany({ orderBy: { id: "asc" } })\n}\n',
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))

    const tenant = findings.find(f => f.title.startsWith('Query sem escopo de tenant'))
    expect(tenant).toBeDefined()
    expect(tenant!.severity).toBe('low')

    const enc = findings.find(f => f.title === 'Criptografia em trânsito/repouso não evidenciada')
    expect(enc).toBeDefined()
    expect(enc!.severity).toBe('low')
  })

  it('NÃO flagga tenant-isolation quando o termo sensível está LONGE da query (round 3: FP do articles.service)', async () => {
    // Repro do FP real do Veredicto: um service de CONTEÚDO (artigos) menciona "token"
    // (publicShareToken) e "benefício" (numa string de prompt) LONGE das queries — o gate
    // file-level classificava o arquivo inteiro como sensível e flaggava TODOS os findMany.
    const filler = Array.from({ length: 30 }, (_, i) => `  const x${i} = ${i}`).join('\n')
    await writeFile(
      join(repoDir, 'articles.ts'),
      `export class ArticlesService {\n` +
      `  async findByShareToken(token: string) { return prisma.article.findFirst({ where: { publicShareToken: token } }) }\n` +
      filler + '\n' +
      `  async listAll() { return prisma.article.findMany({ orderBy: { id: 'asc' } }) }\n` +
      filler + '\n' +
      `  buildPrompt() { return 'meta description com benefício + CTA' }\n`,
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const tenant = findings.filter(f => f.title.startsWith('Query sem escopo de tenant'))
    // listAll() (findMany de artigo) está longe de qualquer dado PESSOAL → não deve flaggar.
    expect(tenant.some(f => /articles\.ts:\d+/.test(f.evidence ?? '') && /listAll|:3[0-9]|:6[0-9]/.test(f.evidence ?? ''))).toBe(false)
  })

  it('AINDA flagga tenant-isolation quando dado sensível está PERTO da query (recall preservado)', async () => {
    await writeFile(
      join(repoDir, 'users.ts'),
      'export function list() {\n  // busca por cpf do titular\n  return prisma.user.findMany({ where: { active: true } })\n}\n',
    )
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings.some(f => f.title.startsWith('Query sem escopo de tenant'))).toBe(true)
  })

  it('walks subdirs and ignores node_modules', async () => {
    await mkdir(join(repoDir, 'src'), { recursive: true })
    await mkdir(join(repoDir, 'node_modules', 'pkg'), { recursive: true })
    await writeFile(join(repoDir, 'src', 'deep.ts'), 'logger.info(`token=${t}`)\n')
    await writeFile(join(repoDir, 'node_modules', 'pkg', 'i.ts'), 'console.log(`cpf=${x}`)\n')

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const logs = findings.filter(f => f.title.startsWith('Possível dado sensível em log'))
    expect(logs).toHaveLength(1)
    expect(logs[0].evidence).toContain('src/deep.ts')
    expect(logs[0].evidence).toContain('token')
  })

  it('ignora .worktrees/.claude (worktrees) — não duplica achados (#40)', async () => {
    await mkdir(join(repoDir, 'src'), { recursive: true })
    await mkdir(join(repoDir, '.worktrees', 'wt-a', 'src'), { recursive: true })
    await mkdir(join(repoDir, '.claude', 'worktrees', 'wt-b', 'src'), { recursive: true })
    await writeFile(join(repoDir, 'src', 'deep.ts'), 'logger.info(`token=${t}`)\n')
    await writeFile(join(repoDir, '.worktrees', 'wt-a', 'src', 'deep.ts'), 'logger.info(`token=${t}`)\n')
    await writeFile(join(repoDir, '.claude', 'worktrees', 'wt-b', 'src', 'deep.ts'), 'logger.info(`token=${t}`)\n')

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const logs = findings.filter(f => f.title.startsWith('Possível dado sensível em log'))
    expect(logs).toHaveLength(1) // só a árvore principal
    expect(logs[0].evidence).toContain('src/deep.ts')
    expect(logs.some(f => /worktrees/.test(f.evidence ?? ''))).toBe(false)
  })

  it('returns no findings on a clean, non-sensitive repo', async () => {
    await writeFile(join(repoDir, 'index.ts'), 'console.log("hello world")\n')
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings).toHaveLength(0)
  })

  it('gera inventário de dados (ROPA) do schema Prisma + mapa de operadores das deps', async () => {
    await writeFile(
      join(repoDir, 'schema.prisma'),
      'model User {\n  id    String @id\n  email String\n  cpf   String\n  nome  String\n}\nmodel AuditLog {\n  id     String @id\n  action String\n}\n',
    )
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { stripe: '^1', '@aws-sdk/client-s3': '^3', openai: '^4' } }),
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))

    const inv = findings.find(f => f.title.startsWith('Inventário de dados pessoais'))
    expect(inv).toBeDefined()
    expect(inv!.severity).toBe('info')
    expect(inv!.description).toContain('User')
    expect(inv!.description).toContain('cpf')
    // AuditLog (sem dado pessoal) NÃO entra no inventário
    expect(inv!.description).not.toContain('AuditLog')

    const ops = findings.find(f => f.title.startsWith('Operadores/sub-processadores'))
    expect(ops).toBeDefined()
    expect(ops!.severity).toBe('info')
    expect(ops!.description).toContain('transferência internacional')
    expect(ops!.evidence).toContain('Stripe')
  })

  // ---- Check 7: divergência POLÍTICA×CÓDIGO (o diferencial LGPD-nativo) ----
  const COMPLIANT_POLICY_TSX = `export default function P() {
    return (
      <main>
        <h1>Política de Privacidade</h1>
        <h2>Operadores</h2>
        <p>Stripe (pagamento), Resend (e-mail), Sentry (erros).</p>
        <h2>Transferência internacional</h2>
        <p>Alguns operadores processam dados fora do Brasil, com base no Art. 33.</p>
        <p>O titular pode revogar o consentimento. Retenção conforme a lei. Cookies usados.</p>
      </main>
    )
  }`

  it('Check 7: política declara internacional mas OMITE operador do código → divergência (sem FP no que está declarado)', async () => {
    await mkdir(join(repoDir, 'app', 'privacidade'), { recursive: true })
    await writeFile(join(repoDir, 'app', 'privacidade', 'page.tsx'), COMPLIANT_POLICY_TSX)
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { stripe: '^1', resend: '^6', '@sentry/nextjs': '^8', openai: '^4' } }),
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))

    // internacional está declarada (§Art.33) → NÃO deve haver finding de transferência não declarada
    expect(findings.find(f => f.title.startsWith('Transferência internacional não declarada'))).toBeUndefined()

    // OpenAI está no código mas não na política → divergência real
    const div = findings.find(f => f.title.startsWith('Operadores no código ausentes da política'))
    expect(div).toBeDefined()
    expect(div!.severity).toBe('low')
    expect(div!.evidence).toContain('OpenAI')
    expect(div!.evidence).not.toContain('Stripe') // declarado → não acusa
    expect(div!.evidence).toContain('app/privacidade/page.tsx') // aponta a política conferida
  })

  it('Check 7: código faz transferência internacional mas a política é silenciosa (Art. 33 não declarado)', async () => {
    await writeFile(
      join(repoDir, 'PRIVACIDADE.md'),
      '# Política de Privacidade\n\n## Operadores\nUsamos terceiros sob contrato.\n\n## Direitos\nO titular exerce direitos. Base legal: consentimento. Retenção legal. Cookies. Encarregado.\n',
    )
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { stripe: '^1' } }),
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const intl = findings.find(f => f.title.startsWith('Transferência internacional não declarada'))
    expect(intl).toBeDefined()
    expect(intl!.severity).toBe('low')
    expect(intl!.evidence).toContain('Stripe')
    expect(intl!.evidence).toContain('PRIVACIDADE.md')
  })

  it('Check 7 (FURO DE HONESTIDADE): política que NEGA transferência intl + código a faz → finding de CONTRADIÇÃO', async () => {
    // O pior caso da marca "não mente": a política afirma que NÃO transfere para fora do
    // Brasil, mas o código usa Stripe/OpenAI (internacional). Tem de FLAGGAR (não escapar).
    await writeFile(
      join(repoDir, 'PRIVACIDADE.md'),
      '# Política de Privacidade\n\n## Transferência internacional\n' +
        'Não realizamos transferência internacional de dados. Todos os dados permanecem no Brasil.\n\n' +
        '## Operadores\nTerceiros sob contrato. Base legal: consentimento. Retenção legal. Cookies. Encarregado.\n',
    )
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { stripe: '^1', openai: '^4' } }),
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const contra = findings.find(f => /internacional NEGADA|contradiz/i.test(f.title))
    expect(contra).toBeDefined()
    expect(contra!.severity).toBe('medium') // mais grave que a mera omissão (low): a política MENTE
    expect(contra!.evidence).toContain('Stripe')
    expect(contra!.evidence).toContain('PRIVACIDADE.md')
    // NÃO deve degradar para o finding de "não declarada" (que diz "nenhuma menção") — seria mentira:
    // a política MENCIONA (para negar). O achado correto é o de contradição.
    expect(findings.find(f => f.title.startsWith('Transferência internacional não declarada'))).toBeUndefined()
  })

  it('Check 7 (GUARD DE RECALL): política que DECLARA honestamente a transferência intl NÃO gera contradição', async () => {
    await mkdir(join(repoDir, 'app', 'privacidade'), { recursive: true })
    await writeFile(join(repoDir, 'app', 'privacidade', 'page.tsx'), COMPLIANT_POLICY_TSX)
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { stripe: '^1', resend: '^6', '@sentry/nextjs': '^8' } }),
    )

    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    expect(findings.find(f => /internacional NEGADA|contradiz/i.test(f.title))).toBeUndefined()
    expect(findings.find(f => f.title.startsWith('Transferência internacional não declarada'))).toBeUndefined()
  })

  it('Check 7: operadores no código mas nenhuma política no repo → nota honesta (não verificável)', async () => {
    await writeFile(
      join(repoDir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { stripe: '^1' } }),
    )
    const findings = await new ComplianceAgent().run(scopeFor(repoDir))
    const note = findings.find(f => f.title.startsWith('Divergência política×código não verificável'))
    expect(note).toBeDefined()
    expect(note!.severity).toBe('info')
  })
})
