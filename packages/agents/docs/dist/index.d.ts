import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class DocsAgent implements SecurityAgent {
    private readonly explicitRepoPath?;
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    /**
     * `explicitRepoPath` é um override (ex.: o comando `fracta docs --docs-path`).
     * No `scan`, fica indefinido e o repo vem de `target.repoPath`. SEM nenhum dos
     * dois, o agente PULA (SkippedCheck) — jamais cai no `process.cwd()`, que
     * escanearia o próprio Fracta e produziria achados desonestos.
     */
    constructor(explicitRepoPath?: string | undefined);
    run(scope: ScanScope): Promise<Finding[]>;
    private auditFile;
    private checkDuplicateTitles;
    private collectMarkdownFiles;
    private walkDir;
}

export { DocsAgent };
