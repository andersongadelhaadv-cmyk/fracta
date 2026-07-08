import { ScanReport, AuditReport, Severity, Finding } from '@fracta/core';

/**
 * SARIF 2.1.0 — o formato que o GitHub Code Scanning ingere. Transforma o
 * Fracta de "relatório" em CONTROL de CI: os achados aparecem inline no diff da
 * PR, e o `fractaFindingId` (id estável) é o fingerprint que o GitHub usa para
 * rastrear/dedup/suprimir o MESMO achado entre runs — o diff por-finding.
 */
interface Sarif {
    $schema: string;
    version: '2.1.0';
    runs: Array<{
        tool: {
            driver: {
                name: string;
                version: string;
                informationUri: string;
                rules: SarifRule[];
            };
        };
        results: SarifResult[];
    }>;
}
interface SarifRule {
    id: string;
    name: string;
    shortDescription: {
        text: string;
    };
    defaultConfiguration: {
        level: SarifLevel;
    };
}
interface SarifResult {
    ruleId: string;
    level: SarifLevel;
    message: {
        text: string;
    };
    locations: Array<{
        physicalLocation: {
            artifactLocation: {
                uri: string;
            };
            region?: {
                startLine: number;
            };
        };
    }>;
    partialFingerprints: {
        fractaFindingId: string;
    };
}
type SarifLevel = 'error' | 'warning' | 'note';
declare function toSarif(report: ScanReport | AuditReport, opts?: {
    toolVersion?: string;
}): Sarif;

/**
 * Classifica UM finding numa categoria OWASP 2021 (ou LGPD/unclassified) por
 * SINAIS EXPLÍCITOS — token A0X:2021, CWE mapeado, código OWASP-API, ou categoria
 * de agente de alta confiança (deps→A06, compliance→LGPD). Nunca chuta: sem sinal
 * confiável → 'unclassified' (honestidade > cobertura fake).
 */
declare function classifyOwasp(finding: Finding): string;
interface ScorecardRow {
    id: string;
    name: string;
    count: number;
    maxSeverity: Severity | 'none';
}
/**
 * Rollup dos findings por categoria OWASP 2021 → um scorecard de postura ("limpo
 * em 7, exposto em 3"). Mostra SEMPRE as 10 categorias (cobertura visível, mesmo
 * as limpas); LGPD e "não classificado" só aparecem quando têm achados.
 */
declare function buildScorecard(findings: Finding[]): ScorecardRow[];

interface ReporterOptions {
    outputDir?: string;
    /** Versão do Fracta gravada no SARIF (`tool.driver.version`). */
    toolVersion?: string;
}
declare class FractaReporter {
    private readonly outputDir;
    private readonly toolVersion;
    constructor(options?: ReporterOptions);
    save(report: ScanReport | AuditReport): Promise<{
        mdPath: string;
        jsonPath: string;
        sarifPath: string;
    }>;
    private buildMarkdown;
    /**
     * Callout de veredito INCONCLUSIVO. A auditoria não conseguiu exercer o alvo
     * (tipicamente staging fora do ar), então a ausência de achados NÃO significa
     * "seguro" — deixa isso explícito no topo, com o motivo concreto.
     */
    /**
     * Scorecard de POSTURA por OWASP Top 10 2021 — sintetiza os achados numa foto de
     * maturidade ("limpo em N, exposto em M"), o que clientes (jurídico/LGPD) leem melhor
     * que uma lista. Classificação por sinal explícito (CWE/OWASP), nunca chute.
     */
    private buildOwaspScorecard;
    private buildInconclusiveCallout;
    /**
     * Bloco de ação prioritária no topo do relatório. Quando a borda LLM produziu
     * uma `prioritization`, respeita exatamente essa ordem ("o que resolver primeiro")
     * e mostra o racional. Sem LLM, cai no determinístico: lista critical + high.
     * Nunca inventa nada — só referencia findings que existem no relatório.
     */
    private buildPriorityBlock;
    /**
     * Renderiza a correção PROPOSTA (gated) de um finding, se houver. Mostra
     * descrição, comando e/ou diff e — sempre — o risco de aplicar. Deixa explícito
     * que o Fracta NUNCA aplica a correção sozinho (regra 2/6).
     */
    private renderProposedFix;
    /**
     * Transparência sobre o que NÃO foi verificado. Parte da robustez:
     * "não verificado" ≠ "seguro". Lista checks com erro e checks pulados.
     */
    private buildTransparencySection;
}

export { FractaReporter, type ReporterOptions, type Sarif, type ScorecardRow, buildScorecard, classifyOwasp, toSarif };
