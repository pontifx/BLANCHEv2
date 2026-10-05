import type { OsintFinding, OsintNarrative, OsintToolExecution } from '../../../shared-schema/src';

export function buildHeuristicNarrative(input: {
  primaryHostname: string;
  findings: OsintFinding[];
  toolExecutions: OsintToolExecution[];
}): OsintNarrative {
  const categoryCounts = countBy(input.findings.map((finding) => finding.category));
  const completedTools = input.toolExecutions.filter((tool) => tool.status === 'completed').length;
  const skippedTools = input.toolExecutions.filter((tool) => tool.status === 'skipped').length;

  const topCategories = Object.entries(categoryCounts)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([category, count]) => `${category} (${count})`);

  const followOnFocus = new Set<string>();
  if ((categoryCounts.hostname ?? 0) > 0) {
    followOnFocus.add('Review related public hostnames and third-party endpoints before deeper testing begins.');
  }
  if ((categoryCounts['archive-reference'] ?? 0) > 0) {
    followOnFocus.add('Compare archived URL references against the current application map to spot legacy attack surface.');
  }
  if ((categoryCounts['security-contact'] ?? 0) === 0) {
    followOnFocus.add('No public security.txt contact was observed; plan coordination channels separately.');
  }
  if ((categoryCounts['technology-hint'] ?? 0) > 0) {
    followOnFocus.add('Use public technology hints to prioritize manual review paths, not to infer vulnerabilities.');
  }
  if (followOnFocus.size === 0) {
    followOnFocus.add('Use the informational OSINT findings to guide scope familiarization and request prioritization.');
  }

  return {
    headline: `Public OSINT summary for ${input.primaryHostname}`,
    summary:
      input.findings.length === 0
        ? `No normalized OSINT findings were produced for ${input.primaryHostname}. Completed tools: ${completedTools}; skipped tools: ${skippedTools}.`
        : `Collected ${input.findings.length} informational findings for ${input.primaryHostname}. The strongest current themes are ${topCategories.join(', ')}. Completed tools: ${completedTools}; skipped tools: ${skippedTools}.`,
    followOnFocus: [...followOnFocus],
    reportReadyNotes: [
      'This output is informational OSINT only and does not validate vulnerabilities or business impact.',
      'Skipped tools usually indicate local environment gaps rather than absence of public data.',
      'Counts and summaries should be used to prioritize manual testing, not replace it.'
    ]
  };
}

function countBy(values: string[]): Record<string, number> {
  return values.reduce<Record<string, number>>((accumulator, value) => {
    accumulator[value] = (accumulator[value] ?? 0) + 1;
    return accumulator;
  }, {});
}
