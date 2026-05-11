import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class RaceAgent implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    run(scope: ScanScope): Promise<Finding[]>;
    private runBurst;
    private runTimingProbe;
    private measureLogin;
}

export { RaceAgent };
