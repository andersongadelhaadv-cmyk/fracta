// src/index.ts
import { mkdir, writeFile } from "fs/promises";
import { join } from "path";

// src/sarif.ts
var LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note"
};
function slug(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}
function ruleIdFor(f) {
  return `${f.category}/${slug(f.agent)}`;
}
function toSarif(report, opts = {}) {
  const findings = report.findings ?? [];
  const rules = /* @__PURE__ */ new Map();
  const results = findings.map((f) => {
    const id = ruleIdFor(f);
    if (!rules.has(id)) {
      rules.set(id, {
        id,
        name: `${f.agent} (${f.category})`,
        shortDescription: { text: `Achados de ${f.agent}` },
        defaultConfiguration: { level: LEVEL[f.severity] }
      });
    }
    const uri = f.location?.file?.trim() || f.endpoint?.trim() || report.target;
    const region = f.location?.line ? { startLine: f.location.line } : void 0;
    return {
      ruleId: id,
      level: LEVEL[f.severity],
      message: { text: f.description ? `${f.title} \u2014 ${f.description}` : f.title },
      locations: [{ physicalLocation: { artifactLocation: { uri }, ...region ? { region } : {} } }],
      partialFingerprints: { fractaFindingId: f.id }
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Fracta",
            version: opts.toolVersion ?? "0.0.0",
            informationUri: "https://fracta.pro",
            rules: [...rules.values()]
          }
        },
        results
      }
    ]
  };
}

// src/scorecard.ts
var OWASP_2021 = [
  { id: "A01", name: "Broken Access Control" },
  { id: "A02", name: "Cryptographic Failures" },
  { id: "A03", name: "Injection" },
  { id: "A04", name: "Insecure Design" },
  { id: "A05", name: "Security Misconfiguration" },
  { id: "A06", name: "Vulnerable and Outdated Components" },
  { id: "A07", name: "Identification and Authentication Failures" },
  { id: "A08", name: "Software and Data Integrity Failures" },
  { id: "A09", name: "Security Logging and Monitoring Failures" },
  { id: "A10", name: "Server-Side Request Forgery" }
];
var CWE_TO_OWASP = {
  "639": "A01",
  "285": "A01",
  "200": "A01",
  "352": "A01",
  "862": "A01",
  "347": "A02",
  "311": "A02",
  "319": "A02",
  "79": "A03",
  "89": "A03",
  "94": "A03",
  "78": "A03",
  "77": "A03",
  "362": "A04",
  "16": "A05",
  "693": "A05",
  "942": "A05",
  "208": "A07",
  "287": "A07",
  "307": "A07",
  "798": "A07",
  "918": "A10"
};
var APICAT_TO_OWASP = {
  "0xa1": "A01",
  "0xa3": "A01",
  "0xa5": "A01",
  "0xa2": "A07"
};
var SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function classifyOwasp(finding) {
  const hay = [finding.title, finding.description, ...finding.references ?? []].join(" ");
  const explicit = hay.match(/\bA(\d{2}):2021\b/i);
  if (explicit) return `A${explicit[1]}`;
  const cwe = hay.match(/(?:CWE-|definitions\/)(\d+)/i);
  if (cwe && CWE_TO_OWASP[cwe[1]]) return CWE_TO_OWASP[cwe[1]];
  const api = hay.match(/0xa[0-9]/i);
  if (api && APICAT_TO_OWASP[api[0].toLowerCase()]) return APICAT_TO_OWASP[api[0].toLowerCase()];
  if (finding.category === "deps") return "A06";
  if (finding.category === "compliance") return "LGPD";
  return "unclassified";
}
var EXTRA_NAMES = {
  LGPD: "Privacidade / LGPD (fora do OWASP Top 10)",
  unclassified: "N\xE3o classificado"
};
function buildScorecard(findings) {
  const acc = /* @__PURE__ */ new Map();
  for (const cat of OWASP_2021) acc.set(cat.id, { count: 0, rank: -1 });
  for (const f of findings) {
    const id = classifyOwasp(f);
    const cur = acc.get(id) ?? { count: 0, rank: -1 };
    cur.count += 1;
    cur.rank = Math.max(cur.rank, SEV_RANK[f.severity]);
    acc.set(id, cur);
  }
  const rankToSev = (r) => r < 0 ? "none" : ["info", "low", "medium", "high", "critical"][r];
  const rows = OWASP_2021.map((cat) => {
    const a = acc.get(cat.id);
    return { id: cat.id, name: cat.name, count: a.count, maxSeverity: rankToSev(a.rank) };
  });
  for (const id of ["LGPD", "unclassified"]) {
    const a = acc.get(id);
    if (a && a.count > 0) rows.push({ id, name: EXTRA_NAMES[id], count: a.count, maxSeverity: rankToSev(a.rank) });
  }
  return rows;
}

// src/index.ts
function isAuditReport(r) {
  return Array.isArray(r.checks);
}
var SEVERITY_EMOJI = {
  critical: "\u{1F534}",
  high: "\u{1F7E0}",
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
  info: "\u26AA"
};
var FractaReporter = class {
  outputDir;
  toolVersion;
  constructor(options = {}) {
    this.outputDir = options.outputDir ?? "./fracta-reports";
    this.toolVersion = options.toolVersion ?? "0.0.0";
  }
  async save(report) {
    await mkdir(this.outputDir, { recursive: true });
    const slug2 = report.target.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    const ts = new Date(report.startedAt).toISOString().replace(/[:.]/g, "-").replace("T", "_").substring(0, 19);
    const baseName = `${slug2}-${ts}`;
    const mdPath = join(this.outputDir, `${baseName}.md`);
    const jsonPath = join(this.outputDir, `${baseName}.json`);
    const sarifPath = join(this.outputDir, `${baseName}.sarif`);
    await writeFile(mdPath, this.buildMarkdown(report), "utf-8");
    await writeFile(jsonPath, JSON.stringify(report, null, 2), "utf-8");
    await writeFile(sarifPath, JSON.stringify(toSarif(report, { toolVersion: this.toolVersion }), null, 2), "utf-8");
    return { mdPath, jsonPath, sarifPath };
  }
  buildMarkdown(report) {
    const date = new Date(report.startedAt);
    const dateStr = date.toLocaleDateString("pt-BR") + " " + date.toLocaleTimeString("pt-BR");
    const durationSec = (report.durationMs / 1e3).toFixed(1);
    const inconclusive = isAuditReport(report) && report.verdict === "inconclusive";
    const degradados = isAuditReport(report) ? report.resumo?.checksDegradados ?? [] : [];
    const comRessalvas = report.passed && degradados.length > 0;
    const status = inconclusive ? "\u26A0\uFE0F INCONCLUSIVO" : report.passed ? comRessalvas ? "\u2705 PASSOU \u26A0\uFE0F COM RESSALVAS" : "\u2705 PASSOU" : "\u274C FALHOU";
    const severities = ["critical", "high", "medium", "low", "info"];
    const grouped = /* @__PURE__ */ new Map();
    for (const s of severities) grouped.set(s, []);
    for (const f of report.findings) grouped.get(f.severity).push(f);
    let md = `# \u{1F6E1}\uFE0F Fracta \u2014 Relat\xF3rio de Seguran\xE7a

`;
    md += `| Campo | Valor |
|---|---|
`;
    md += `| Target | ${report.target} |
`;
    md += `| Data | ${dateStr} |
`;
    md += `| Dura\xE7\xE3o | ${durationSec}s |
`;
    md += `| Run ID | \`${report.runId}\` |
`;
    md += `| Status | ${status} |

`;
    if (inconclusive) {
      md += this.buildInconclusiveCallout(report);
    } else if (comRessalvas) {
      md += `> \u2705 **PASSOU \u2014 COM RESSALVAS.** ${degradados.length} verifica\xE7\xE3o(\xF5es) cr\xEDtica(s) N\xC3O rodou(aram): `;
      md += `**${degradados.join(", ")}**.
`;
      md += `> A **aus\xEAncia de achado nesses checks N\xC3O significa "seguro"** \u2014 apenas que n\xE3o foram executados `;
      md += `(ex.: depend\xEAncia faltando, como o gitleaks). Instale/habilite a capacidade e rode de novo.

`;
    }
    md += `## \u{1F4CA} Resumo

`;
    md += `| Severidade | Quantidade |
|---|---|
`;
    md += `| \u{1F534} Critical | ${report.summary.critical} |
`;
    md += `| \u{1F7E0} High | ${report.summary.high} |
`;
    md += `| \u{1F7E1} Medium | ${report.summary.medium} |
`;
    md += `| \u{1F535} Low | ${report.summary.low} |
`;
    md += `| \u26AA Info | ${report.summary.info} |
`;
    md += `| **Total** | **${report.summary.total}** |

`;
    md += this.buildOwaspScorecard(report);
    md += this.buildPriorityBlock(report);
    const severityTitles = {
      critical: "\u{1F534} CR\xCDTICO",
      high: "\u{1F7E0} ALTO",
      medium: "\u{1F7E1} M\xC9DIO",
      low: "\u{1F535} BAIXO",
      info: "\u26AA INFORMATIVO"
    };
    for (const severity of severities) {
      const findings = grouped.get(severity);
      if (findings.length === 0) continue;
      md += `## ${severityTitles[severity]} (${findings.length})

`;
      for (const f of findings) {
        md += `### ${f.title}

`;
        md += `**Agente:** \`${f.agent}\` | **Categoria:** \`${f.category}\`
`;
        if (f.confidence === "low") {
          md += `**Confian\xE7a:** \u{1F535} baixa \u2014 heur\xEDstico ou em arquivo propenso a falso-positivo (teste/fixture/exemplo). Para revis\xE3o; **n\xE3o** derruba o build.
`;
        }
        if (f.endpoint) md += `**Endpoint:** \`${f.endpoint}\`
`;
        md += `
${f.description}

`;
        if (f.evidence) {
          md += `**Evid\xEAncia:**
\`\`\`
${f.evidence}
\`\`\`

`;
        }
        md += `**Corre\xE7\xE3o:** ${f.recommendation}

`;
        md += this.renderProposedFix(f);
        if (f.references && f.references.length > 0) {
          md += `**Refer\xEAncias:** ${f.references.map((r) => `[${r}](${r})`).join(" \xB7 ")}

`;
        }
        md += `---

`;
      }
    }
    if (isAuditReport(report)) {
      md += this.buildTransparencySection(report);
    }
    md += `---

`;
    md += `*Gerado pelo [Fracta](https://fracta.pro?ref=report&utm_source=fracta-report&utm_medium=report&utm_campaign=footer) \u2014 auditoria de seguran\xE7a gr\xE1tis e open-source para SaaS. Monitoramento cont\xEDnuo + regress\xE3o em [fracta.pro](https://fracta.pro?ref=report).*
`;
    md += `*Feito pela PreviusIA, tamb\xE9m criadora do [zap-api.tech](https://zap-api.tech?ref=fracta-report&utm_source=fracta-report&utm_medium=report&utm_campaign=crosssell) \u2014 API de WhatsApp para devs.*
`;
    return md;
  }
  /**
   * Callout de veredito INCONCLUSIVO. A auditoria não conseguiu exercer o alvo
   * (tipicamente staging fora do ar), então a ausência de achados NÃO significa
   * "seguro" — deixa isso explícito no topo, com o motivo concreto.
   */
  /**
   * Scorecard de POSTURA por OWASP Top 10 2021 — sintetiza os achados numa foto de
   * maturidade ("limpo em N, exposto em M"), o que clientes (jurídico/LGPD) leem melhor
   * que uma lista. Classificação por sinal explícito (CWE/OWASP), nunca chute.
   */
  buildOwaspScorecard(report) {
    const rows = buildScorecard(report.findings);
    const owasp = rows.filter((r) => /^A\d\d$/.test(r.id));
    const limpas = owasp.filter((r) => r.count === 0).length;
    const emoji = { critical: "\u{1F534}", high: "\u{1F7E0}", medium: "\u{1F7E1}", low: "\u{1F535}", info: "\u26AA", none: "\u2705" };
    let md = `## \u{1F3AF} Postura por OWASP Top 10 (2021)

`;
    md += `Limpo em **${limpas}/10** categorias. Classifica\xE7\xE3o por sinal expl\xEDcito (CWE/OWASP-API); o que n\xE3o tem sinal confi\xE1vel fica em "N\xE3o classificado" (honestidade > cobertura fake).

`;
    md += `| Categoria | Achados | Pior | Status |
|---|---|---|---|
`;
    for (const r of rows) {
      const status = r.maxSeverity === "none" ? "\u2705 sem achados" : `${emoji[r.maxSeverity]} ${r.maxSeverity}`;
      md += `| ${r.id} \u2014 ${r.name} | ${r.count} | ${r.maxSeverity === "none" ? "\u2014" : r.maxSeverity} | ${status} |
`;
    }
    return md + "\n";
  }
  buildInconclusiveCallout(report) {
    const h = report.targetHealth;
    const comErro = report.resumo?.checksComErro ?? [];
    const motivo = h.stagingResponding === false ? "o alvo (staging) n\xE3o respondeu \u2014 a camada DAST n\xE3o p\xF4de ser exercida." : h.repoAccessible === false ? "o reposit\xF3rio obrigat\xF3rio est\xE1 inacess\xEDvel \u2014 n\xE3o houve o que auditar." : comErro.length > 0 ? `${comErro.length} verifica\xE7\xE3o(\xF5es) falhou(aram) com erro (${comErro.join(", ")}) \u2014 essa(s) dimens\xE3o(\xF5es) N\xC3O foi(ram) medida(s).` : "o alvo n\xE3o p\xF4de ser exercido nesta execu\xE7\xE3o.";
    let md = `> \u26A0\uFE0F **Veredito INCONCLUSIVO:** ${motivo}
`;
    md += `> **Aus\xEAncia de achados aqui N\xC3O significa "seguro"** \u2014 apenas que a auditoria n\xE3o rodou de ponta a ponta.
`;
    md += `> Garanta que o alvo est\xE1 no ar e rode de novo.

`;
    return md;
  }
  /**
   * Bloco de ação prioritária no topo do relatório. Quando a borda LLM produziu
   * uma `prioritization`, respeita exatamente essa ordem ("o que resolver primeiro")
   * e mostra o racional. Sem LLM, cai no determinístico: lista critical + high.
   * Nunca inventa nada — só referencia findings que existem no relatório.
   */
  buildPriorityBlock(report) {
    const byId = new Map(report.findings.map((f) => [f.id, f]));
    const prioritization = isAuditReport(report) ? report.prioritization : void 0;
    if (prioritization && prioritization.order.length > 0) {
      const ordered = prioritization.order.map((id) => byId.get(id)).filter((f) => f !== void 0);
      if (ordered.length > 0) {
        let md2 = `## \u{1F3AF} A\xE7\xE3o Priorit\xE1ria

`;
        md2 += `> Ordem sugerida pela borda LLM (prioriza por contexto do SaaS; **n\xE3o** altera severidade nem o conjunto de achados).

`;
        ordered.forEach((f, i) => {
          md2 += `${i + 1}. ${SEVERITY_EMOJI[f.severity]} **${f.title}** \u2014 \`${f.agent}\`
`;
        });
        if (prioritization.rationale) {
          md2 += `
> ${prioritization.rationale.trim().replace(/\n+/g, "\n> ")}
`;
        }
        md2 += `
`;
        return md2;
      }
    }
    const topo = report.findings.filter(
      (f) => (f.severity === "critical" || f.severity === "high") && f.confidence !== "low"
    );
    if (topo.length === 0) return "";
    let md = `## \u{1F3AF} A\xE7\xE3o Priorit\xE1ria (${topo.length})

`;
    md += `> Achados de severidade **cr\xEDtica/alta** \u2014 tratar primeiro.

`;
    for (const f of topo) {
      md += `- ${SEVERITY_EMOJI[f.severity]} **${f.title}** \u2014 \`${f.agent}\`
`;
    }
    md += `
`;
    return md;
  }
  /**
   * Renderiza a correção PROPOSTA (gated) de um finding, se houver. Mostra
   * descrição, comando e/ou diff e — sempre — o risco de aplicar. Deixa explícito
   * que o Fracta NUNCA aplica a correção sozinho (regra 2/6).
   */
  renderProposedFix(f) {
    const fix = f.proposedFix;
    if (!fix) return "";
    let md = `**\u{1F527} Corre\xE7\xE3o proposta (gated \u2014 n\xE3o aplicada automaticamente):**

`;
    md += `${fix.description}

`;
    if (fix.command) {
      md += `\`\`\`bash
${fix.command}
\`\`\`

`;
    }
    if (fix.diff) {
      md += `\`\`\`diff
${fix.diff}
\`\`\`

`;
    }
    md += `**Risco de aplicar:** ${fix.riskOfApplying}

`;
    return md;
  }
  /**
   * Transparência sobre o que NÃO foi verificado. Parte da robustez:
   * "não verificado" ≠ "seguro". Lista checks com erro e checks pulados.
   */
  buildTransparencySection(report) {
    const { resumo } = report;
    let md = "";
    if (resumo.regressoes > 0) {
      md += `## \u23EA Regress\xF5es (${resumo.regressoes})

`;
      const regs = report.findings.filter((f) => f.status === "regression");
      for (const f of regs) {
        md += `- **${f.title}** (\`${f.agent}\`, ${f.severity}) \u2014 voltou a aparecer.
`;
      }
      md += `
`;
    }
    if (resumo.checksComErro.length > 0 || resumo.checksPulados.length > 0) {
      md += `## \u26A0\uFE0F Checks que N\xC3O rodaram

`;
      md += `> Estes checks n\xE3o produziram veredito. Aus\xEAncia de achado aqui **n\xE3o** significa "seguro".

`;
      const byAgent = new Map(report.checks.map((c) => [c.agent, c]));
      if (resumo.checksComErro.length > 0) {
        md += `**Erro (falha isolada):**

`;
        for (const agent of resumo.checksComErro) {
          md += `- \`${agent}\` \u2014 ${byAgent.get(agent)?.motivo ?? "erro n\xE3o especificado"}
`;
        }
        md += `
`;
      }
      if (resumo.checksPulados.length > 0) {
        md += `**Pulados (sem dados de entrada):**

`;
        for (const agent of resumo.checksPulados) {
          md += `- \`${agent}\` \u2014 ${byAgent.get(agent)?.motivo ?? "sem motivo registrado"}
`;
        }
        md += `
`;
      }
    }
    return md;
  }
};
export {
  FractaReporter,
  buildScorecard,
  classifyOwasp,
  toSarif
};
