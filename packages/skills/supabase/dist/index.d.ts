import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

interface SupabaseSkillOptions {
    anonKey?: string;
}
declare class SupabaseSkill implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    private readonly anonKey?;
    constructor(options?: SupabaseSkillOptions);
    run(scope: ScanScope): Promise<Finding[]>;
    private probeRestRoot;
    private probeStorage;
    private probeAnonReads;
}

export { SupabaseSkill, type SupabaseSkillOptions };
