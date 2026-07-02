// src/index.ts
import { mkdir, writeFile } from "fs/promises";
import { join } from "path";
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
  constructor(options = {}) {
    this.outputDir = options.outputDir ?? "./fracta-reports";
  }
  async save(report) {
    await mkdir(this.outputDir, { recursive: true });
    const slug = report.target.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    const ts = new Date(report.startedAt).toISOString().replace(/[:.]/g, "-").replace("T", "_").substring(0, 19);
    const baseName = `${slug}-${ts}`;
    const mdPath = join(this.outputDir, `${baseName}.md`);
    const jsonPath = join(this.outputDir, `${baseName}.json`);
    await writeFile(mdPath, this.buildMarkdown(report), "utf-8");
    await writeFile(jsonPath, JSON.stringify(report, null, 2), "utf-8");
    return { mdPath, jsonPath };
  }
  buildMarkdown(report) {
    const date = new Date(report.startedAt);
    const dateStr = date.toLocaleDateString("pt-BR") + " " + date.toLocaleTimeString("pt-BR");
    const durationSec = (report.durationMs / 1e3).toFixed(1);
    const inconclusive = isAuditReport(report) && report.verdict === "inconclusive";
    const status = inconclusive ? "\u26A0\uFE0F INCONCLUSIVO" : report.passed ? "\u2705 PASSOU" : "\u274C FALHOU";
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
    md += `*Gerado pelo [Fracta](https://github.com/fracta/fracta) \u2014 The Complete SaaS Audit Framework*
`;
    return md;
  }
  /**
   * Callout de veredito INCONCLUSIVO. A auditoria não conseguiu exercer o alvo
   * (tipicamente staging fora do ar), então a ausência de achados NÃO significa
   * "seguro" — deixa isso explícito no topo, com o motivo concreto.
   */
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
  FractaReporter
};
