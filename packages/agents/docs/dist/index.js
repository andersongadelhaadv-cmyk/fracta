// src/index.ts
import { readdir, readFile, stat } from "fs/promises";
import { join, relative } from "path";
import { stableFindingId } from "@fracta/core";
var IGNORE_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", "dist", ".next", "coverage", ".turbo"]);
var LEGACY_PATTERNS = /old|legado|legacy|deprecated|backup|v1\.|_old\.|antigo/i;
var MS_IN_DAY = 864e5;
var DocsAgent = class {
  constructor(repoPath = process.cwd()) {
    this.repoPath = repoPath;
  }
  repoPath;
  name = "DOCS Agent";
  category = "docs";
  concurrency = 1;
  timeoutMs = 6e4;
  async run(scope) {
    const findings = [];
    try {
      const files = await this.collectMarkdownFiles(this.repoPath);
      if (files.length === 0) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "docs-none" }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "info",
          title: "Nenhum arquivo .md encontrado",
          description: `Nenhum arquivo Markdown encontrado em ${this.repoPath}`,
          recommendation: "Adicione documenta\xE7\xE3o Markdown ao reposit\xF3rio.",
          createdAt: /* @__PURE__ */ new Date()
        });
        return findings;
      }
      const h1Titles = /* @__PURE__ */ new Map();
      for (const file of files) {
        await this.auditFile(scope, file, findings, h1Titles);
      }
      this.checkDuplicateTitles(scope, h1Titles, findings);
    } catch (err) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: "docs-read-error" }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "info",
        title: "DOCS Agent \u2014 erro ao ler reposit\xF3rio",
        description: `Erro ao escanear ${this.repoPath}: ${String(err)}`,
        recommendation: "Verifique se o caminho do reposit\xF3rio est\xE1 correto.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    return findings;
  }
  async auditFile(scope, file, findings, h1Titles) {
    const ageMs = Date.now() - file.modifiedAt.getTime();
    const ageDays = Math.floor(ageMs / MS_IN_DAY);
    if (ageDays > 180) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-stale:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "medium",
        title: `Documenta\xE7\xE3o obsoleta: ${file.relativePath}`,
        description: `Arquivo n\xE3o modificado h\xE1 ${ageDays} dias (>180 dias).`,
        endpoint: file.relativePath,
        recommendation: "Revise e atualize o arquivo ou adicione uma nota de deprecia\xE7\xE3o no topo.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    if (LEGACY_PATTERNS.test(file.relativePath)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-legacy-name:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "medium",
        title: `Arquivo com nome legado: ${file.relativePath}`,
        description: "Nome do arquivo sugere conte\xFAdo legado, backup ou depreciado.",
        endpoint: file.relativePath,
        recommendation: "Remova o arquivo se for obsoleto, ou renomeie e documente o status atual.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    if (/TODO|FIXME/i.test(file.content)) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-todo:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "low",
        title: `TODOs n\xE3o resolvidos: ${file.relativePath}`,
        description: "Arquivo cont\xE9m marca\xE7\xF5es TODO ou FIXME indicando documenta\xE7\xE3o incompleta.",
        endpoint: file.relativePath,
        recommendation: "Resolva os TODOs ou abra issues para rastre\xE1-los.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    const v1Matches = (file.content.match(/\bv[01]\b/gi) ?? []).length;
    if (v1Matches > 2) {
      findings.push({
        id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-legacy-version-refs:${file.relativePath}`, location: file.relativePath }),
        runId: scope.runId,
        agent: this.name,
        category: this.category,
        camada: this.category,
        severity: "medium",
        title: `Refer\xEAncias a vers\xF5es legadas: ${file.relativePath}`,
        description: `${v1Matches} refer\xEAncias a v0/v1 encontradas. Pode indicar documenta\xE7\xE3o desatualizada.`,
        endpoint: file.relativePath,
        recommendation: "Verifique se as refer\xEAncias a vers\xF5es antigas s\xE3o intencionais ou precisam ser atualizadas.",
        createdAt: /* @__PURE__ */ new Date()
      });
    }
    const h1Match = file.content.match(/^#\s+(.+)$/m);
    if (h1Match) {
      const title = h1Match[1].trim();
      const existing = h1Titles.get(title) ?? [];
      h1Titles.set(title, [...existing, file.relativePath]);
    }
  }
  checkDuplicateTitles(scope, h1Titles, findings) {
    for (const [title, paths] of h1Titles) {
      if (paths.length > 1) {
        findings.push({
          id: stableFindingId({ saas: scope.target.name, camada: this.category, rule: `doc-duplicate-h1:${title}` }),
          runId: scope.runId,
          agent: this.name,
          category: this.category,
          camada: this.category,
          severity: "low",
          title: `T\xEDtulo H1 duplicado: "${title}"`,
          description: `O mesmo t\xEDtulo H1 aparece em ${paths.length} arquivos: ${paths.join(", ")}`,
          recommendation: "Use t\xEDtulos \xFAnicos para facilitar navega\xE7\xE3o e indexa\xE7\xE3o.",
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    }
  }
  async collectMarkdownFiles(dir) {
    const files = [];
    await this.walkDir(dir, dir, files);
    return files;
  }
  async walkDir(dir, baseDir, files) {
    let entries;
    try {
      entries = await readdir(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry)) continue;
      const fullPath = join(dir, entry);
      try {
        const info = await stat(fullPath);
        if (info.isDirectory()) {
          await this.walkDir(fullPath, baseDir, files);
        } else if (entry.endsWith(".md")) {
          const content = await readFile(fullPath, "utf-8");
          files.push({
            path: fullPath,
            content,
            modifiedAt: info.mtime,
            relativePath: relative(baseDir, fullPath).replace(/\\/g, "/")
          });
        }
      } catch {
      }
    }
  }
};
export {
  DocsAgent
};
