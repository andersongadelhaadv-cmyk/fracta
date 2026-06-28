type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
/** Status de um Finding entre execuções (ver regressão/supressão na Fase 2). */
type FindingStatus = 'open' | 'suppressed' | 'regression';
type AgentCategory = 'security' | 'docs' | 'code' | 'deps' | 'secrets' | 'infra' | 'compliance' | 'performance';
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
/** Acesso a infra de um alvo (opcional — ausência → checks de infra ficam `skipped`). */
interface TargetInfra {
    host?: string;
    sshConfigPath?: string;
    dockerComposePath?: string;
}
interface TargetFrontend {
    framework: 'next' | 'react' | 'none';
    envFiles?: string[];
}
interface TargetConfig {
    /** IDs de findings já revisados como falso-positivo (ver Fase 2). */
    suppressions?: string[];
    severityThreshold?: Severity;
}
interface Target {
    name: string;
    url: string;
    stack: StackType[];
    auth?: TargetAuth;
    agents?: string[];
    skills?: string[];
    ignore?: string[];
    /** Caminho local do repositório clonado (para agentes baseados em repo/SAST). */
    repoPath?: string;
    infra?: TargetInfra;
    frontend?: TargetFrontend;
    config?: TargetConfig;
}
/**
 * Correção PROPOSTA por um agente/LLM. NUNCA aplicada automaticamente (regra 2/6).
 * `riskOfApplying` é obrigatório: honestidade sobre o que pode quebrar.
 */
interface ProposedFix {
    description: string;
    diff?: string;
    command?: string;
    riskOfApplying: string;
}
interface Finding {
    id: string;
    runId: string;
    agent: string;
    category: AgentCategory;
    /** Camada de auditoria. Default = `category` quando o agente não distingue. */
    camada?: AgentCategory;
    severity: Severity;
    /** Estado entre execuções. Preenchido pelo store na Fase 2; default `open`. */
    status?: FindingStatus;
    title: string;
    description: string;
    endpoint?: string;
    evidence?: string;
    recommendation: string;
    /** Correção gated, opcional — preenchida pela borda LLM (Fase 6). */
    proposedFix?: ProposedFix;
    references?: string[];
    createdAt: Date;
}
interface ScanScope {
    target: Target;
    depth: ScanDepth;
    agents: string[];
    runId: string;
    startedAt: Date;
    /** Saúde do alvo medida no preflight (Fase 3). Agentes podem consultar p/ decidir skip. */
    health?: TargetHealth;
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
/**
 * Hash estável e determinístico para o `id` de um Finding.
 * Mesmo achado → sempre o mesmo id. É o que faz regressão e supressão funcionarem (Fase 2).
 * Derivado de `saas + camada + regra + localização normalizada`.
 */
declare function stableFindingId(parts: {
    saas: string;
    camada: string;
    rule: string;
    location?: string;
}): string;
/**
 * Sinaliza que um check não rodou por falta de input (sem repoPath, stack incompatível,
 * staging não fornecido...). O orquestrador transforma em `CheckResult.status = 'skipped'`.
 * "Não verificado" ≠ "seguro". Qualquer outro throw vira `status: 'error'`.
 */
declare class SkippedCheck extends Error {
    readonly motivo: string;
    constructor(motivo: string);
}
type CheckStatus = 'ok' | 'error' | 'skipped';
/** Resultado isolado de UM agente. Um check nunca derruba os outros (regra 4). */
interface CheckResult {
    agent: string;
    camada: AgentCategory;
    status: CheckStatus;
    /** Motivo quando status é `error` ou `skipped`. */
    motivo?: string;
    durationMs: number;
    findings: Finding[];
}
type TargetHealthStatus = 'healthy' | 'degraded' | 'unreachable';
interface TargetHealth {
    repoAccessible: boolean;
    stagingResponding?: boolean;
    vpsReachable?: boolean;
    status: TargetHealthStatus;
}
/**
 * Porta de persistência entre execuções (regressão/supressão). O core define o
 * contrato; a implementação concreta (SQLite) vive em `@fracta/store` e é injetada
 * pelo cli/mcp — assim o core não depende de nenhum backend de armazenamento.
 */
interface FindingStore {
    /**
     * Define `status` de cada finding com base no histórico:
     * - id em `suppressions` → `suppressed`
     * - id que existia e havia sido resolvido/ausente, e voltou → `regression`
     * - id inédito ou já aberto → `open`
     * Persiste o histórico (firstSeen/lastSeen/resolved). Retorna os findings com status.
     */
    applyStatus(saas: string, findings: Finding[], suppressions: string[]): Finding[] | Promise<Finding[]>;
    /** Persiste o run completo (para painel/comparação futura). */
    recordRun(report: AuditReport): void | Promise<void>;
}
/**
 * Priorização produzida pela borda LLM (Fase 6) — ordem de finding ids "o que
 * resolver primeiro" + racional. Não altera severidade nem o conjunto de findings.
 */
interface Prioritization {
    order: string[];
    rationale?: string;
}
/**
 * Relatório consolidado de uma auditoria de UM SaaS. Superset de `ScanReport`
 * (mantém os campos antigos para compatibilidade) + camada de robustez.
 */
interface AuditReport extends ScanReport {
    saas: string;
    timestamp: string;
    targetHealth: TargetHealth;
    checks: CheckResult[];
    resumo: {
        porSeveridade: Record<Severity, number>;
        regressoes: number;
        checksComErro: string[];
        checksPulados: string[];
    };
    /** Preenchido pela borda LLM, se habilitada (opcional). */
    prioritization?: Prioritization;
}
/**
 * Pós-processamento opcional do relatório pela borda LLM. Implementação concreta
 * em `@fracta/llm`, injetada pelo cli/mcp. A detecção NUNCA depende disto — se o
 * enricher falhar ou não houver API key, o relatório determinístico segue intacto.
 */
interface ReportEnricher {
    enrich(report: AuditReport): Promise<AuditReport>;
}

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
    /** Persistência opcional para regressão/supressão (injetada pelo cli/mcp). */
    store?: FindingStore;
    /** Preflight de saúde do alvo. Default: checkTargetHealth. Injetável p/ testes. */
    healthCheck?: (target: Target) => Promise<TargetHealth>;
    /** Borda LLM opcional (prioriza + redige correções). Detecção não depende dela. */
    enricher?: ReportEnricher;
}
declare class FractaOrchestrator {
    private agents;
    private readonly options;
    private readonly store?;
    private readonly healthCheck;
    private readonly enricher?;
    constructor(options?: OrchestratorOptions);
    registerAgent(agent: SecurityAgent): this;
    registerAgents(agents: SecurityAgent[]): this;
    scan(target: Target): Promise<AuditReport>;
    scanAll(targets: Target[]): Promise<AuditReport[]>;
    /**
     * Executa UM agente de forma isolada: aplica timeout, captura qualquer falha
     * e devolve sempre um CheckResult (ok | error | skipped). Nunca propaga exceção.
     */
    private runCheckIsolated;
    /**
     * Auditoria abortada por repo obrigatório inacessível. Devolve um AuditReport
     * honesto (nenhum check rodou, não passou) sem persistir nada.
     */
    private buildAbortedReport;
    private printSummary;
}

/**
 * Verificação de saúde do alvo ANTES de auditar (Lacuna 1 do guia). Um alvo fora
 * do ar ou um repo inexistente nunca pode ser interpretado como "tudo seguro".
 * Tudo é read-only e tolerante a falha — qualquer erro vira "não respondeu".
 */
declare function checkTargetHealth(target: Target): Promise<TargetHealth>;
interface HealthInputs {
    hasRepo: boolean;
    repoAccessible: boolean;
    stagingApplicable: boolean;
    stagingResponding?: boolean;
    vpsApplicable: boolean;
    vpsReachable?: boolean;
}
/**
 * Deriva o status agregado (lógica pura, testável). Repo obrigatório inacessível
 * é fatal (`unreachable` → o orquestrador aborta). Para os probes externos opcionais:
 * todos de pé = healthy; alguns = degraded; nenhum = unreachable.
 */
declare function deriveHealthStatus(p: HealthInputs): TargetHealthStatus;

interface CommandResult {
    stdout: string;
    stderr: string;
    code: number | null;
}
interface RunCommandOptions {
    cwd?: string;
    timeoutMs?: number;
    /** Texto a enviar no stdin do processo (ex.: para ferramentas que leem stdin). */
    input?: string;
}
type CommandRunner = (command: string, args: string[], opts?: RunCommandOptions) => Promise<CommandResult>;
/**
 * Executa um comando externo de forma read-only e captura stdout/stderr.
 * Compartilhado pelos agentes baseados em repositório (npm audit, gitleaks...).
 * Rejeita com ENOENT se o binário não existe (o agente decide skip vs error) e
 * com erro de timeout se estourar o prazo. Nunca usa a saída para escrever nada.
 */
declare const runCommand: CommandRunner;

export { type AgentCategory, type AuditReport, type CheckResult, type CheckStatus, type CommandResult, type CommandRunner, type Finding, type FindingStatus, type FindingStore, FractaHttpClient, FractaOrchestrator, type FractaSkill, type HealthInputs, type HttpResponse, KNOWN_STACKS, type OrchestratorOptions, type Prioritization, type ProposedFix, type ReportEnricher, type RequestOptions, type RunCommandOptions, type ScanDepth, type ScanReport, type ScanScope, type SecurityAgent, type SecurityTest, type Severity, SkippedCheck, type StackType, type Target, type TargetAuth, type TargetConfig, type TargetFrontend, type TargetHealth, type TargetHealthStatus, type TargetInfra, checkTargetHealth, deriveHealthStatus, makeFinding, runCommand, stableFindingId };
