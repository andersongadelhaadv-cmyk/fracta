type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type AgentCategory = 'security' | 'docs' | 'code' | 'deps' | 'infra' | 'compliance' | 'performance';
type StackType = string;
declare const KNOWN_STACKS: readonly ["nestjs", "nextjs", "prisma", "stripe", "supabase", "whatsapp", "redis", "docker"];
type ScanDepth = 'quick' | 'full' | 'paranoid';
interface TargetAuth {
    type: 'jwt' | 'apikey' | 'basic' | 'oauth';
    endpoint?: string;
    credentials?: {
        email?: string;
        password?: string;
        apiKey?: string;
    };
    headerName?: string;
    headerPrefix?: string;
}
interface Target {
    name: string;
    url: string;
    stack: StackType[];
    auth?: TargetAuth;
    agents?: string[];
    skills?: string[];
    ignore?: string[];
}
interface Finding {
    id: string;
    runId: string;
    agent: string;
    category: AgentCategory;
    severity: Severity;
    title: string;
    description: string;
    endpoint?: string;
    evidence?: string;
    recommendation: string;
    references?: string[];
    createdAt: Date;
}
interface ScanScope {
    target: Target;
    depth: ScanDepth;
    agents: string[];
    runId: string;
    startedAt: Date;
}
interface ScanReport {
    runId: string;
    target: string;
    startedAt: Date;
    finishedAt: Date;
    durationMs: number;
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    findings: Finding[];
    passed: boolean;
}
interface SecurityAgent {
    name: string;
    category: AgentCategory;
    concurrency: number;
    timeoutMs: number;
    run(scope: ScanScope): Promise<Finding[]>;
}
interface HttpResponse {
    status: number;
    headers: Record<string, string>;
    body: unknown;
    raw: string;
}
interface RequestOptions {
    method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    headers?: Record<string, string>;
    body?: unknown;
    timeoutMs?: number;
}
interface SecurityTest {
    name: string;
    path: string;
    method: RequestOptions['method'];
    headers?: Record<string, string>;
    body?: unknown;
    expect: (response: HttpResponse) => Finding[];
}
interface FractaSkill {
    name: string;
    targets: StackType[];
    detect(target: Target): boolean;
    getTests(): SecurityTest[];
    evaluate(response: HttpResponse): Finding[];
}
declare function makeFinding(partial: Omit<Finding, 'id' | 'createdAt'>): Finding;

declare class FractaHttpClient {
    private readonly baseUrl;
    private readonly baseHeaders;
    constructor(baseUrl: string, baseHeaders?: Record<string, string>);
    request(path: string, options?: RequestOptions): Promise<HttpResponse>;
    withHeaders(extra: Record<string, string>): FractaHttpClient;
    static withJwt(baseUrl: string, authEndpoint: string, credentials: {
        email: string;
        password: string;
    }): Promise<{
        client: FractaHttpClient;
        token: string;
    }>;
}

interface OrchestratorOptions {
    concurrency?: number;
    failOn?: Severity[];
    depth?: ScanDepth;
    verbose?: boolean;
}
declare class FractaOrchestrator {
    private agents;
    private readonly options;
    constructor(options?: OrchestratorOptions);
    registerAgent(agent: SecurityAgent): this;
    registerAgents(agents: SecurityAgent[]): this;
    scan(target: Target): Promise<ScanReport>;
    scanAll(targets: Target[]): Promise<ScanReport[]>;
    private printSummary;
}

export { type AgentCategory, type Finding, FractaHttpClient, FractaOrchestrator, type FractaSkill, type HttpResponse, KNOWN_STACKS, type OrchestratorOptions, type RequestOptions, type ScanDepth, type ScanReport, type ScanScope, type SecurityAgent, type SecurityTest, type Severity, type StackType, type Target, type TargetAuth, makeFinding };
