// src/index.ts
import { FractaHttpClient, stableFindingId } from "@fracta/core";
var COMMON_TABLES = [
  "users",
  "profiles",
  "accounts",
  "customers",
  "orders",
  "invoices",
  "subscriptions",
  "messages",
  "notifications",
  "logs"
];
var COMMON_BUCKETS = ["avatars", "public", "uploads", "documents", "attachments"];
function looksLikeSupabaseError(body) {
  return /\b(PGRST|JWT expired|No API key|Invalid API key|permission denied for table)\b/i.test(body);
}
var SupabaseSkill = class {
  name = "Supabase Skill";
  category = "security";
  concurrency = 2;
  timeoutMs = 6e4;
  anonKey;
  constructor(options = {}) {
    this.anonKey = options.anonKey ?? process.env.SUPABASE_ANON_KEY;
  }
  async run(scope) {
    const findings = [];
    const { target } = scope;
    if (!target.stack?.includes("supabase")) return findings;
    const client = new FractaHttpClient(target.url);
    const ignore = target.ignore ?? [];
    await this.probeRestRoot(scope, client, findings, ignore);
    await this.probeStorage(scope, client, findings, ignore);
    if (this.anonKey) {
      await this.probeAnonReads(scope, client, findings, ignore);
    }
    return findings;
  }
  async probeRestRoot(scope, client, findings, ignore) {
    const path = "/rest/v1/";
    if (ignore.some((i) => path.startsWith(i))) return;
    try {
      const res = await client.request(path, { timeoutMs: 4e3 });
      if (res.status === 200 && res.raw.length > 10) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `supabase-rest-root:${path}`, location: path }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "medium",
          title: `Supabase REST root acess\xEDvel sem chave: ${path}`,
          description: `${path} respondeu 200 sem header apikey/Authorization. O REST root exp\xF5e a estrutura de tabelas e prepara IDOR e enumera\xE7\xE3o.`,
          endpoint: path,
          evidence: `GET ${path} \u2192 HTTP 200 (${res.raw.length} bytes)
${res.raw.substring(0, 200).replace(/\s+/g, " ").trim()}`,
          recommendation: "Coloque um WAF/edge function rejeitando requests sem apikey, ou use Supabase pr\xF3ximo ao banco com Row Level Security ativada em TODAS as tabelas \u2014 RLS off + REST p\xFAblico = banco aberto.",
          references: [
            "https://supabase.com/docs/guides/database/postgres/row-level-security",
            "https://supabase.com/docs/guides/api"
          ],
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    } catch {
    }
  }
  async probeStorage(scope, client, findings, ignore) {
    for (const bucket of COMMON_BUCKETS) {
      const path = `/storage/v1/object/list/${bucket}`;
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await client.request(path, {
          method: "POST",
          body: { prefix: "", limit: 5 },
          timeoutMs: 4e3
        });
        if (res.status === 200 && res.raw.length > 5 && !looksLikeSupabaseError(res.raw)) {
          findings.push({
            id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `supabase-storage-list:${bucket}`, location: path }),
            runId: scope.runId,
            agent: this.name,
            category: this.category,
            camada: this.category,
            severity: "high",
            title: `Bucket Storage list\xE1vel sem auth: ${bucket}`,
            description: `POST em ${path} retornou listagem (HTTP 200, ${res.raw.length} bytes) sem credenciais. Bucket "${bucket}" permite enumera\xE7\xE3o de objetos por qualquer um.`,
            endpoint: path,
            evidence: `POST ${path} \u2192 HTTP 200
${res.raw.substring(0, 200).replace(/\s+/g, " ").trim()}`,
            recommendation: "Restrinja listagem em buckets p\xFAblicos \u2014 apenas o GET direto a um path conhecido deve ser permitido:\n```sql\ncreate policy \"no public listing\" on storage.objects\n  for select using (auth.role() = 'authenticated');\n```",
            references: ["https://supabase.com/docs/guides/storage/security/access-control"],
            createdAt: /* @__PURE__ */ new Date()
          });
          return;
        }
      } catch {
      }
    }
  }
  async probeAnonReads(scope, client, findings, ignore) {
    const anonClient = client.withHeaders({
      apikey: this.anonKey,
      Authorization: `Bearer ${this.anonKey}`
    });
    for (const table of COMMON_TABLES) {
      const path = `/rest/v1/${table}?select=*&limit=3`;
      if (ignore.some((i) => path.startsWith(i))) continue;
      try {
        const res = await anonClient.request(path, { timeoutMs: 4e3 });
        if (res.status !== 200) continue;
        try {
          const data = JSON.parse(res.raw);
          if (Array.isArray(data) && data.length > 0) {
            findings.push({
              id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `supabase-rls-off:${table}`, location: path }),
              runId: scope.runId,
              agent: this.name,
              category: this.category,
              camada: this.category,
              severity: "critical",
              title: `RLS off \u2014 tabela "${table}" lida com anon key`,
              description: `GET ${path} retornou ${data.length} linhas usando apenas a anon key. A tabela "${table}" est\xE1 com Row Level Security desativada ou com policy permissiva \u2014 qualquer cliente do frontend (e qualquer atacante) l\xEA esses dados.`,
              endpoint: path,
              evidence: `GET ${path} \u2192 200, ${data.length} rows
${res.raw.substring(0, 200).replace(/\s+/g, " ").trim()}`,
              recommendation: "Habilite RLS e crie policies por user:\n```sql\nalter table public." + table + ' enable row level security;\ncreate policy "user reads own row" on public.' + table + "\n  for select using (auth.uid() = user_id);\n```",
              references: [
                "https://supabase.com/docs/guides/database/postgres/row-level-security",
                "https://cwe.mitre.org/data/definitions/284.html"
              ],
              createdAt: /* @__PURE__ */ new Date()
            });
          }
        } catch {
        }
      } catch {
      }
    }
  }
};
export {
  SupabaseSkill
};
