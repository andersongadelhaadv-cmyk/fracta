import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class IdorAgent implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    run(scope: ScanScope): Promise<Finding[]>;
    private testEnumeration;
}

export { IdorAgent };
