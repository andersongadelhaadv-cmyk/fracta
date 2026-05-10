// src/index.ts
import { mkdir, writeFile } from "fs/promises";
import { join } from "path";
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
    const status = report.passed ? "\u2705 PASSOU" : "\u274C FALHOU";
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
        if (f.references && f.references.length > 0) {
          md += `**Refer\xEAncias:** ${f.references.map((r) => `[${r}](${r})`).join(" \xB7 ")}

`;
        }
        md += `---

`;
      }
    }
    md += `*Gerado pelo [Fracta](https://github.com/fracta/fracta) \u2014 The Complete SaaS Audit Framework*
`;
    return md;
  }
};
export {
  FractaReporter
};
