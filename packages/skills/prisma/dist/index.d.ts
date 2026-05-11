import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class PrismaSkill implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    run(scope: ScanScope): Promise<Finding[]>;
    private probeStudio;
    private probeErrorLeak;
}

export { PrismaSkill };
