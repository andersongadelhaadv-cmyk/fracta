import { resolveTxt as dnsResolveTxt, resolveMx as dnsResolveMx } from 'node:dns/promises'
import { isIP } from 'node:net'
import type { SecurityAgent, ScanScope, Finding, AgentCategory, Severity, ProposedFix } from '@fracta/core'
import { stableFindingId } from '@fracta/core'

/** Resolver DNS injetável (default: node:dns). Permite testes herméticos, sem rede. */
export interface DnsResolver {
  resolveTxt(name: string): Promise<string[][]>
  resolveMx(name: string): Promise<Array<{ exchange: string; priority: number }>>
}

const defaultResolver: DnsResolver = {
  resolveTxt: (n) => dnsResolveTxt(n),
  resolveMx: (n) => dnsResolveMx(n),
}

export type SpfAll = 'fail' | 'softfail' | 'neutral' | 'pass' | 'none'
export type DmarcPolicy = 'none' | 'quarantine' | 'reject'

export interface EmailDnsResult {
  domain: string
  hasMx: boolean
  spf: { present: boolean; record?: string; all?: SpfAll }
  dmarc: { present: boolean; record?: string; policy?: DmarcPolicy; pct?: number }
  dkim: { probed: string[]; found: string[] }
}

/** DNS divide TXT longos em vários chunks — junta antes de parsear. */
const joinTxt = (chunks: string[]): string => chunks.join('')

export function parseSpf(records: string[][]): EmailDnsResult['spf'] {
  const rec = records.map(joinTxt).find((r) => /^v=spf1\b/i.test(r.trim()))
  if (!rec) return { present: false }
  const m = rec.match(/([-~?+])all\b/i)
  const map: Record<string, SpfAll> = { '-': 'fail', '~': 'softfail', '?': 'neutral', '+': 'pass' }
  return { present: true, record: rec, all: m ? map[m[1]] : 'none' }
}

export function parseDmarc(records: string[][]): EmailDnsResult['dmarc'] {
  const rec = records.map(joinTxt).find((r) => /^v=dmarc1\b/i.test(r.trim()))
  if (!rec) return { present: false }
  const p = rec.match(/\bp\s*=\s*(none|quarantine|reject)\b/i)
  const pct = rec.match(/\bpct\s*=\s*(\d+)\b/i)
  return {
    present: true,
    record: rec,
    policy: (p?.[1]?.toLowerCase() as DmarcPolicy) ?? 'none',
    pct: pct ? Number(pct[1]) : undefined,
  }
}

const DKIM_SELECTORS = ['google', 'default', 'selector1', 'selector2', 'k1', 'resend', 's1', 'dkim']

// Domínios com TLD de 2 níveis comuns (BR + alguns) — p/ achar o domínio registrável.
const TWO_LEVEL_TLD = new Set(['com.br', 'adv.br', 'net.br', 'org.br', 'gov.br', 'eng.br', 'co.uk', 'com.au'])

/** Domínio registrável (eTLD+1) — SPF/DMARC vivem aqui, não no subdomínio. */
export function registrableDomain(host: string): string {
  const labels = host.replace(/^www\./i, '').replace(/\.$/, '').toLowerCase().split('.')
  if (labels.length <= 2) return labels.join('.')
  const last2 = labels.slice(-2).join('.')
  return TWO_LEVEL_TLD.has(last2) ? labels.slice(-3).join('.') : last2
}

/** Postura de e-mail/DNS: SPF, DMARC, MX e DKIM (best-effort). Determinístico. */
export async function analyzeEmailDns(domain: string, resolver: DnsResolver = defaultResolver): Promise<EmailDnsResult> {
  const safe = async <T>(p: Promise<T>, fb: T): Promise<T> => {
    try { return await p } catch { return fb }
  }
  const [txt, mx, dmarcTxt] = await Promise.all([
    safe(resolver.resolveTxt(domain), [] as string[][]),
    safe(resolver.resolveMx(domain), [] as Array<{ exchange: string; priority: number }>),
    safe(resolver.resolveTxt(`_dmarc.${domain}`), [] as string[][]),
  ])
  const probes = await Promise.all(
    DKIM_SELECTORS.map(async (sel) => {
      const r = await safe(resolver.resolveTxt(`${sel}._domainkey.${domain}`), [] as string[][])
      const has = r.map(joinTxt).some((x) => /v=dkim1|k=rsa|(^|;)\s*p=/i.test(x))
      return has ? sel : null
    }),
  )
  return {
    domain,
    hasMx: mx.length > 0,
    spf: parseSpf(txt),
    dmarc: parseDmarc(dmarcTxt),
    dkim: { probed: DKIM_SELECTORS, found: probes.filter((s): s is string => s !== null) },
  }
}

const REFS = ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://datatracker.ietf.org/doc/html/rfc7489']

/**
 * Postura de e-mail/DNS (anti-spoofing/phishing). Determinístico (registros DNS são
 * fatos → confiança alta). SPF/DMARC protegem o domínio contra falsificação do "From"
 * — importa mesmo sem MX, porque phishing usa o NOME do domínio.
 */
export class DnsAgent implements SecurityAgent {
  name = 'DNS Agent'
  category: AgentCategory = 'security'
  concurrency = 1
  timeoutMs = 15_000

  constructor(private readonly resolver: DnsResolver = defaultResolver) {}

  async run(scope: ScanScope): Promise<Finding[]> {
    let host: string
    try { host = new URL(scope.target.url).hostname } catch { return [] }
    // IP ou host de 1 label (localhost/interno) não tem SPF/DMARC — pula (nada a auditar).
    if (isIP(host) || !host.includes('.')) return []
    const domain = registrableDomain(host)
    const r = await analyzeEmailDns(domain, this.resolver)
    return this.toFindings(scope, r)
  }

  private make(scope: ScanScope, rule: string, severity: Severity, title: string, description: string, recommendation: string, proposedFix?: ProposedFix, evidence?: string): Finding {
    return {
      id: stableFindingId({ saas: scope.target.name, camada: this.category, rule }),
      runId: scope.runId,
      agent: this.name,
      category: this.category,
      camada: this.category,
      severity,
      confidence: 'high', // registro DNS é fato
      title,
      description,
      recommendation,
      references: REFS,
      createdAt: new Date(),
      ...(proposedFix ? { proposedFix } : {}),
      ...(evidence ? { evidence } : {}),
    }
  }

  private toFindings(scope: ScanScope, r: EmailDnsResult): Finding[] {
    const out: Finding[] = []
    const d = r.domain
    // Prioridade escala com uso de e-mail: domínio COM MX (envia/recebe) = medium;
    // sem MX (não usa e-mail) = low — spoofing ainda é possível, mas prioridade menor.
    const missSev: Severity = r.hasMx ? 'medium' : 'low'
    const noMxHint = r.hasMx ? '' : ' (o domínio não tem MX — mesmo assim, o NOME pode ser forjado; o ideal é travar com "-all"/p=reject).'

    // SPF
    if (!r.spf.present) {
      out.push(this.make(scope, 'dns-spf-missing', missSev,
        `Sem registro SPF em ${d}`,
        `O domínio ${d} não tem registro SPF (TXT v=spf1). Sem SPF, é mais fácil forjar e-mails com o seu domínio (phishing) — receptores não sabem quais servidores podem enviar em seu nome.${noMxHint}`,
        'Publique um registro SPF listando seus servidores de envio e termine com "-all" (hardfail). Se o domínio não envia e-mail, use apenas "v=spf1 -all".',
        {
          description: `Adicione um TXT no host "@" de ${d}: se NÃO envia e-mail, use exatamente  v=spf1 -all . Se envia, liste os remetentes e termine com -all, ex.:  v=spf1 include:_spf.resend.com -all .`,
          riskOfApplying: 'PROPOSTA — não aplicada. Se você envia e-mail, liste TODOS os remetentes (provedor transacional, ERP, etc.) ANTES de "-all", senão e-mail legítimo é rejeitado.',
        }))
    } else if (r.spf.all === 'pass') {
      out.push(this.make(scope, 'dns-spf-permissive', 'high',
        `SPF permissivo (+all) em ${d}`,
        `O SPF de ${d} termina com "+all", que autoriza QUALQUER servidor a enviar e-mail em nome do domínio — equivale a não ter proteção e facilita spoofing.`,
        'Troque "+all" por "-all" (hardfail), listando apenas os servidores de envio legítimos.',
        {
          description: `No TXT do host "@" de ${d}, troque o " +all " final por " -all ", mantendo os includes dos seus remetentes legítimos.`,
          riskOfApplying: 'PROPOSTA — confirme que todos os remetentes estão nos includes antes de trocar por -all.',
        },
        r.spf.record))
    } else if (r.spf.all === 'neutral') {
      out.push(this.make(scope, 'dns-spf-neutral', 'low',
        `SPF neutro (?all) em ${d}`,
        `O SPF de ${d} usa "?all" (neutral): não afirma nada sobre remetentes não listados, então não protege efetivamente contra spoofing.`,
        'Use "-all" (hardfail) ou ao menos "~all" (softfail) em vez de "?all".',
        {
          description: `No TXT do host "@" de ${d}, troque " ?all " por " -all " (mantendo os includes dos remetentes legítimos).`,
          riskOfApplying: 'PROPOSTA — confirme os remetentes antes de -all; se preferir cauteloso, use "~all".',
        },
        r.spf.record))
    }

    // DMARC
    if (!r.dmarc.present) {
      out.push(this.make(scope, 'dns-dmarc-missing', missSev,
        `Sem registro DMARC em ${d}`,
        `O domínio ${d} não tem DMARC (TXT em _dmarc.${d}). Sem DMARC, mesmo com SPF/DKIM os receptores não têm uma POLÍTICA para barrar e-mails forjados, e você não recebe relatórios de abuso.${noMxHint}`,
        'Publique um DMARC começando por p=none (monitorar) e evolua para p=quarantine e p=reject; use rua= para receber relatórios.',
        {
          description: r.hasMx
            ? `Adicione um TXT no host "_dmarc.${d}":  v=DMARC1; p=none; rua=mailto:dmarc@${d}; fo=1  (monitora, não bloqueia). Após validar os relatórios, evolua para p=quarantine e depois p=reject.`
            : `Adicione um TXT no host "_dmarc.${d}":  v=DMARC1; p=reject  (o domínio não envia e-mail — reject é seguro e trava spoofing de imediato).`,
          riskOfApplying: 'PROPOSTA — p=none NÃO afeta entrega (só monitora). Só suba para quarantine/reject após confirmar que SPF/DKIM alinham no e-mail legítimo.',
        }))
    } else if (r.dmarc.policy === 'none') {
      out.push(this.make(scope, 'dns-dmarc-none', 'low',
        `DMARC em modo monitor (p=none) em ${d}`,
        `O DMARC de ${d} está com p=none: só monitora, NÃO instrui os receptores a barrar e-mail forjado. É o primeiro passo, mas não protege contra spoofing enquanto não endurecer.`,
        'Após validar os relatórios, evolua para p=quarantine e depois p=reject.',
        {
          description: `No TXT "_dmarc.${d}", troque  p=none  por  p=quarantine  (e depois  p=reject ), mantendo o rua=.`,
          riskOfApplying: 'PROPOSTA — suba a régua só após os relatórios rua= mostrarem que o e-mail legítimo passa.',
        },
        r.dmarc.record))
    }

    // DKIM (best-effort, informativo)
    if (r.dkim.found.length === 0 && r.hasMx) {
      out.push(this.make(scope, 'dns-dkim-not-found', 'info',
        `DKIM não detectado nos seletores comuns em ${d}`,
        `O domínio ${d} recebe e-mail (tem MX) mas não encontrei DKIM nos seletores comuns testados (${r.dkim.probed.join(', ')}). Best-effort: você pode usar um seletor diferente — isto é informativo, não penaliza.`,
        'Confirme que o e-mail transacional assina com DKIM (o seletor correto do seu provedor).',
        {
          description: `Ative DKIM no seu provedor de e-mail transacional — ele fornece o seletor e a chave pública a publicar como TXT em  <seletor>._domainkey.${d} .`,
          riskOfApplying: 'PROPOSTA — configuração no provedor; adiciona assinatura, sem quebrar entrega. Confirme o seletor correto.',
        }))
    }

    return out
  }
}
