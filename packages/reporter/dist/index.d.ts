import { ScanReport, AuditReport } from '@fracta/core';

interface ReporterOptions {
    outputDir?: string;
}
declare class FractaReporter {
    private readonly outputDir;
    constructor(options?: ReporterOptions);
    save(report: ScanReport | AuditReport): Promise<{
        mdPath: string;
        jsonPath: string;
    }>;
    private buildMarkdown;
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

export { FractaReporter, type ReporterOptions };
