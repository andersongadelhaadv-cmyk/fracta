import { randomUUID } from 'crypto'
import type { SecurityAgent, ScanScope, Finding, AgentCategory } from '@fracta/core'
import { FractaHttpClient } from '@fracta/core'

const COMMON_TABLES = [
  'users', 'profiles', 'accounts', 'customers',
  'orders', 'invoices', 'subscriptions',
  'messages', 'notifications', 'logs',
]

const COMMON_BUCKETS = ['avatars', 'public', 'uploads', 'documents', 'attachments']

function looksLikeSupabaseError(body: string): boolean {
  return /\b(PGRST|JWT expired|No API key|Invalid API key|permission denied for table)\b/i.test(body)
}

export interface SupabaseSkillOptions {
  anonKey?: string
}

export class SupabaseSkill implements SecurityAgent {
  name = 'Supabase Skill'
  category: AgentCategory = 'security'
  concurrency = 2
  timeoutMs = 60_000

  private readonly anonKey?: string

  constructor(options: SupabaseSkillOptions = {}) {
    this.anonKey = options.anonKey ?? process.env.SUPABASE_ANON_KEY
  }

  async run(scope: ScanScope): Promise<Finding[]> {
    const findings: Finding[] = []
    const { target } = scope

    if (!target.stack.includes('supabase')) return findings

    const client = new FractaHttpClient(target.url)
    const ignore = target.ignore ?? []

    await this.probeRestRoot(scope, client, findings, ignore)
    await this.probeStorage(scope, client, findings, ignore)
    if (this.anonKey) {
      await this.probeAnonReads(scope, client, findings, ignore)
    }

    return findings
  }

  private async probeRestRoot(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    const path = '/rest/v1/'
    if (ignore.some(i => path.startsWith(i))) return

    try {
      const res = await client.request(path, { timeoutMs: 4_000 })
      if (res.status === 200 && res.raw.length > 10) {
        findings.push({
          id: randomUUID(),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          severity: 'medium',
          title: `Supabase REST root acessível sem chave: ${path}`,
          description: `${path} respondeu 200 sem header apikey/Authorization. O REST root expõe a estrutura de tabelas e prepara IDOR e enumeração.`,
          endpoint: path,
          evidence: `GET ${path} → HTTP 200 (${res.raw.length} bytes)\n${res.raw.substring(0, 200).replace(/\s+/g, ' ').trim()}`,
          recommendation: 'Coloque um WAF/edge function rejeitando requests sem apikey, ou use Supabase próximo ao banco com Row Level Security ativada em TODAS as tabelas — RLS off + REST público = banco aberto.',
          references: [
            'https://supabase.com/docs/guides/database/postgres/row-level-security',
            'https://supabase.com/docs/guides/api',
          ],
          createdAt: new Date(),
        })
      }
    } catch { /* ignora */ }
  }

  private async probeStorage(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    for (const bucket of COMMON_BUCKETS) {
      const path = `/storage/v1/object/list/${bucket}`
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await client.request(path, {
          method: 'POST',
          body: { prefix: '', limit: 5 },
          timeoutMs: 4_000,
        })
        if (res.status === 200 && res.raw.length > 5 && !looksLikeSupabaseError(res.raw)) {
          findings.push({
            id: randomUUID(),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            severity: 'high',
            title: `Bucket Storage listável sem auth: ${bucket}`,
            description: `POST em ${path} retornou listagem (HTTP 200, ${res.raw.length} bytes) sem credenciais. Bucket "${bucket}" permite enumeração de objetos por qualquer um.`,
            endpoint: path,
            evidence: `POST ${path} → HTTP 200\n${res.raw.substring(0, 200).replace(/\s+/g, ' ').trim()}`,
            recommendation: 'Restrinja listagem em buckets públicos — apenas o GET direto a um path conhecido deve ser permitido:\n```sql\ncreate policy "no public listing" on storage.objects\n  for select using (auth.role() = \'authenticated\');\n```',
            references: ['https://supabase.com/docs/guides/storage/security/access-control'],
            createdAt: new Date(),
          })
          return
        }
      } catch { /* ignora */ }
    }
  }

  private async probeAnonReads(
    scope: ScanScope,
    client: FractaHttpClient,
    findings: Finding[],
    ignore: string[]
  ): Promise<void> {
    const anonClient = client.withHeaders({
      apikey: this.anonKey!,
      Authorization: `Bearer ${this.anonKey!}`,
    })

    for (const table of COMMON_TABLES) {
      const path = `/rest/v1/${table}?select=*&limit=3`
      if (ignore.some(i => path.startsWith(i))) continue
      try {
        const res = await anonClient.request(path, { timeoutMs: 4_000 })
        if (res.status !== 200) continue

        try {
          const data = JSON.parse(res.raw) as unknown[]
          if (Array.isArray(data) && data.length > 0) {
            findings.push({
              id: randomUUID(),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              severity: 'critical',
              title: `RLS off — tabela "${table}" lida com anon key`,
              description: `GET ${path} retornou ${data.length} linhas usando apenas a anon key. A tabela "${table}" está com Row Level Security desativada ou com policy permissiva — qualquer cliente do frontend (e qualquer atacante) lê esses dados.`,
              endpoint: path,
              evidence: `GET ${path} → 200, ${data.length} rows\n${res.raw.substring(0, 200).replace(/\s+/g, ' ').trim()}`,
              recommendation: 'Habilite RLS e crie policies por user:\n```sql\nalter table public.' + table + ' enable row level security;\ncreate policy "user reads own row" on public.' + table + '\n  for select using (auth.uid() = user_id);\n```',
              references: [
                'https://supabase.com/docs/guides/database/postgres/row-level-security',
                'https://cwe.mitre.org/data/definitions/284.html',
              ],
              createdAt: new Date(),
            })
          }
        } catch { /* não-json */ }
      } catch { /* ignora */ }
    }
  }
}
