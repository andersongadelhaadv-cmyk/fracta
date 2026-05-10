import { ScanReport } from '@fracta/core';

interface ReporterOptions {
    outputDir?: string;
}
declare class FractaReporter {
    private readonly outputDir;
    constructor(options?: ReporterOptions);
    save(report: ScanReport): Promise<{
        mdPath: string;
        jsonPath: string;
    }>;
    private buildMarkdown;
}

export { FractaReporter, type ReporterOptions };
