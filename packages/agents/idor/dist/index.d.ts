import { SecurityAgent, AgentCategory, ScanScope, Finding } from '@fracta/core';

declare class IdorAgent implements SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    run(scope: ScanScope): Promise<Finding[]>;
    /**
     * IDOR cross-tenant REAL (2 contas): autentica A e B, confirma que B acessa os
     * próprios recursos e tenta acessá-los como A. A conseguir = vazamento cross-tenant
     * PROVADO (não heurística). Opt-in via `crossTenant` no targets.yaml; read-only.
     */
    private testCrossTenant;
    private crossTenantInfo;
    private testEnumeration;
}

export { IdorAgent };
