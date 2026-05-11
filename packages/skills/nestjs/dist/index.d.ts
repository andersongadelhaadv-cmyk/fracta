import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class NestJSSkill implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    run(scope: ScanScope): Promise<Finding[]>;
    private probeSwagger;
    private probeHealth;
}

export { NestJSSkill };
