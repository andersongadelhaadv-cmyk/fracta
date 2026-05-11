import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

interface StripeAgentOptions {
    webhookSecret?: string;
}
declare class StripeAgent implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    private readonly webhookSecret?;
    constructor(options?: StripeAgentOptions);
    run(scope: ScanScope): Promise<Finding[]>;
    private discoverWebhookPaths;
    private testEndpoint;
    private safePost;
}

export { StripeAgent, type StripeAgentOptions };
