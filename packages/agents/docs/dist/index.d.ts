import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class DocsAgent implements SecurityAgent {
    private readonly repoPath;
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    constructor(repoPath?: string);
    run(scope: ScanScope): Promise<Finding[]>;
    private auditFile;
    private checkDuplicateTitles;
    private collectMarkdownFiles;
    private walkDir;
}

export { DocsAgent };
