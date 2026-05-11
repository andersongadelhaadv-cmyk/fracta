import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class TenantAgent implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    run(scope: ScanScope): Promise<Finding[]>;
    private probeAdminPaths;
    private probeTenantPaths;
    private probeHeaderInjection;
}

export { TenantAgent };
