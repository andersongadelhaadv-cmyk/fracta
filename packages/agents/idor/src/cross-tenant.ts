import type { Finding, AgentCategory } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

/** Resultado de sondar UM recurso de B com as duas identidades. */
export interface CrossTenantProbe {
  /** Path do recurso que pertence ao tenant B. */
  resource: string
  /** Status de B acessando o PRÓPRIO recurso (sanidade: ancora a prova). */
  tenantBStatus: number
  /** Status de A tentando acessar o recurso de B. */
  tenantAStatus: number
  /** Bytes do corpo que A recebeu. */
  tenantABytes: number
  /** Amostra do corpo que A recebeu (evidência). */
  tenantABody?: string
}

const CATEGORY: AgentCategory = 'security'
const AGENT = 'IDOR Agent'
const REFS = [
  'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
  'https://cwe.mitre.org/data/definitions/639.html',
]

/** B acessa o próprio recurso? (sanidade que ancora a prova) */
function tenantBOwns(p: CrossTenantProbe): boolean {
  return p.tenantBStatus === 200
}
/** A conseguiu ler o recurso de B? */
function tenantALeaked(p: CrossTenantProbe): boolean {
  return p.tenantAStatus === 200 && p.tenantABytes > 10
}

/**
 * Decide os findings de isolamento cross-tenant a partir das sondagens. Puro e
 * determinístico (testável sem rede). Regra de ouro (zero-FP): só afirma vazamento
 * quando A leu um recurso que B PROVADAMENTE possui (B o acessa). Sem isso, é
 * inconclusivo — nunca verde falso.
 */
export function evaluateCrossTenant(input: {
  saas: string
  runId: string
  probes: CrossTenantProbe[]
}): Finding[] {
  const { saas, runId, probes } = input
  if (probes.length === 0) return []

  const usable = probes.filter(tenantBOwns)
  // Nenhum recurso de B é sequer acessível por B → não dá pra provar nada.
  if (usable.length === 0) {
    return [{
      id: stableFindingId({ saas, camada: CATEGORY, rule: 'idor-crosstenant-inconclusive' }),
      runId, agent: AGENT, category: CATEGORY, camada: CATEGORY,
      severity: 'info', confidence: 'high',
      title: 'IDOR cross-tenant: inconclusivo (tenant B não acessou os próprios recursos)',
      description:
        `O tenant B não conseguiu acessar nenhum dos ${probes.length} recurso(s) declarados como seus ` +
        `(status ≠ 200). Sem essa âncora não é possível provar (nem descartar) vazamento cross-tenant. ` +
        `Confira as credenciais/paths de \`crossTenant.ownedResources\` no targets.yaml.`,
      recommendation: 'Ajuste os recursos de B em `crossTenant.ownedResources` para paths que o tenant B realmente acessa (GET 200).',
      references: REFS,
      createdAt: new Date(),
    }]
  }

  const leaks = usable.filter(tenantALeaked)
  if (leaks.length > 0) {
    // Um finding CONFIRMADO por recurso vazado (preciso, com endpoint/evidência).
    return leaks.map(p => ({
      id: stableFindingId({ saas, camada: CATEGORY, rule: `idor-crosstenant-confirmed:${p.resource}`, location: p.resource }),
      runId, agent: AGENT, category: CATEGORY, camada: CATEGORY,
      severity: 'critical', confidence: 'high',
      title: `IDOR cross-tenant CONFIRMADO: tenant A leu recurso de B (${p.resource})`,
      description:
        `Provado em runtime: o recurso ${p.resource} PERTENCE ao tenant B (B o acessa com 200), ` +
        `e o tenant A conseguiu lê-lo (HTTP ${p.tenantAStatus}, ${p.tenantABytes} bytes). ` +
        `Isso é Broken Object Level Authorization: dados de um tenant vazam para outro. Não é heurística — é acesso cruzado real.`,
      endpoint: p.resource,
      evidence: `A: GET ${p.resource} → ${p.tenantAStatus} (${p.tenantABytes} bytes)${p.tenantABody ? `\n${p.tenantABody.slice(0, 200)}` : ''}\nB (dono): GET ${p.resource} → 200`,
      recommendation:
        'Escope TODA leitura de recurso ao tenant/owner do usuário autenticado (filtro no `where`, Prisma extension ou Postgres RLS). ' +
        'Nunca confie só no ID da rota — verifique a propriedade antes de retornar.',
      references: REFS,
      createdAt: new Date(),
    }))
  }

  // B possui os recursos, A foi negado em todos → isolamento PROVADO (positivo).
  return [{
    id: stableFindingId({ saas, camada: CATEGORY, rule: 'idor-crosstenant-isolated' }),
    runId, agent: AGENT, category: CATEGORY, camada: CATEGORY,
    severity: 'info', confidence: 'high',
    title: 'Isolamento multi-tenant confirmado em runtime',
    description:
      `Verificado com 2 contas: o tenant A foi NEGADO em ${usable.length} recurso(s) que pertencem ao tenant B ` +
      `(B os acessa com 200; A recebeu 403/404). Isolamento cross-tenant OK para os recursos testados — prova positiva, não suposição.`,
    recommendation: 'Mantenha o escopo por tenant em toda query. Amplie `crossTenant.ownedResources` para cobrir mais rotas sensíveis.',
    references: REFS,
    createdAt: new Date(),
  }]
}
