import {
  BLANCHE_OSINT_REPORT_KIND,
  BLANCHE_OSINT_SCHEMA_VERSION,
  type BlancheOsintReportV1,
  type BlancheOsintSeedV1,
  type ExportWarning
} from '../../shared-schema/src';
import { buildHeuristicNarrative } from './analysis/heuristicNarrative';
import type { CollectorRunOutput } from './collectors/types';
import { extractRelatedHostnames } from './shared/targeting';

export function buildOsintReport(input: {
  seed: BlancheOsintSeedV1;
  outputs: CollectorRunOutput[];
}): BlancheOsintReportV1 {
  const findings = input.outputs.flatMap((output) => output.findings);
  const toolExecutions = input.outputs.map((output) => output.toolExecution);
  const warnings = dedupeWarnings([
    ...input.seed.warnings,
    ...input.outputs.flatMap((output) => output.warnings)
  ]);
  const errors = input.outputs.flatMap((output) => output.errors);
  const relatedHostnames = extractRelatedHostnames(input.seed);

  const narrative = buildHeuristicNarrative({
    primaryHostname: input.seed.seed.primaryHostname,
    findings,
    toolExecutions
  });
  const findingsByCategory = countBy(findings.map((finding) => finding.category));

  return {
    kind: BLANCHE_OSINT_REPORT_KIND,
    schemaVersion: BLANCHE_OSINT_SCHEMA_VERSION,
    reportMetadata: {
      reportId: createId('osint'),
      generatedAt: new Date().toISOString(),
      generatedBy: {
        product: 'BLANCHE',
        component: 'osint-orchestrator/cli',
        version: '0.1.0'
      },
      seedId: input.seed.seedMetadata.seedId
    },
    scope: input.seed.scope,
    target: {
      primaryHostname: input.seed.seed.primaryHostname,
      apparentRootDomain: input.seed.seed.apparentRootDomain,
      targetUrl: input.seed.seed.targetUrl,
      targetOrigin: input.seed.seed.targetOrigin,
      relatedHostnames
    },
    seed: input.seed,
    toolExecutions,
    findings,
    warnings,
    errors,
    narrative,
    summary: {
      findingCount: findings.length,
      findingsByCategory,
      completedTools: toolExecutions.filter((tool) => tool.status === 'completed').length,
      skippedTools: toolExecutions.filter((tool) => tool.status === 'skipped').length,
      failedTools: toolExecutions.filter((tool) => tool.status === 'failed').length
    }
  };
}

export function renderReportMarkdown(report: BlancheOsintReportV1): string {
  const findingsSection =
    report.findings.length === 0
      ? '- No normalized informational OSINT findings were produced.\n'
      : report.findings
          .map(
            (finding) =>
              `- [${finding.category}] ${finding.title}: ${finding.description} (target: ${finding.target})`
          )
          .join('\n');

  const toolSection = report.toolExecutions
    .map(
      (tool) =>
        `- ${tool.name} [${tool.status}] target=${tool.target} outputs=${tool.outputCount}${
          tool.command ? ` command=\`${tool.command}\`` : ''
        }`
    )
    .join('\n');

  return `# BLANCHE OSINT Summary

Generated: ${report.reportMetadata.generatedAt}
Primary Hostname: ${report.target.primaryHostname}
Target URL: ${report.target.targetUrl ?? '(not provided)'}

## Narrative

${report.narrative.headline}

${report.narrative.summary}

## Follow-On Focus

${report.narrative.followOnFocus.map((line) => `- ${line}`).join('\n')}

## Report-Ready Notes

${report.narrative.reportReadyNotes.map((line) => `- ${line}`).join('\n')}

## Tool Executions

${toolSection}

## Findings

${findingsSection}
`;
}

function dedupeWarnings(warnings: ExportWarning[]): ExportWarning[] {
  const seen = new Set<string>();
  const output: ExportWarning[] = [];
  for (const warning of warnings) {
    const key = JSON.stringify(warning);
    if (!seen.has(key)) {
      seen.add(key);
      output.push(warning);
    }
  }
  return output;
}

function countBy(values: string[]): Record<string, number> {
  return values.reduce<Record<string, number>>((accumulator, value) => {
    accumulator[value] = (accumulator[value] ?? 0) + 1;
    return accumulator;
  }, {});
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
