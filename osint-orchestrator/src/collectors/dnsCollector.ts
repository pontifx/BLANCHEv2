import dns from 'node:dns/promises';
import type { ExportWarning, JsonValue, OsintFinding } from '../../../shared-schema/src';
import type { CollectorDefinition, CollectorRunOutput } from './types';

interface QueryPlan {
  label: string;
  target: string;
  resolve(): Promise<unknown>;
}

export const dnsCollector: CollectorDefinition = {
  id: 'builtin-dns',
  name: 'Built-in DNS Collector',
  async run(context): Promise<CollectorRunOutput> {
    const startedAt = new Date().toISOString();
    const queryTarget = context.apparentRootDomain ?? context.primaryHostname;
    const warnings: ExportWarning[] = [];
    const findings: OsintFinding[] = [];
    const errors: string[] = [];

    const plans: QueryPlan[] = [
      {
        label: 'A',
        target: context.primaryHostname,
        resolve: async () => dns.resolve4(context.primaryHostname)
      },
      {
        label: 'AAAA',
        target: context.primaryHostname,
        resolve: async () => dns.resolve6(context.primaryHostname)
      },
      {
        label: 'CNAME',
        target: context.primaryHostname,
        resolve: async () => dns.resolveCname(context.primaryHostname)
      },
      {
        label: 'MX',
        target: queryTarget,
        resolve: async () => dns.resolveMx(queryTarget)
      },
      {
        label: 'NS',
        target: queryTarget,
        resolve: async () => dns.resolveNs(queryTarget)
      },
      {
        label: 'TXT',
        target: queryTarget,
        resolve: async () => dns.resolveTxt(queryTarget)
      },
      {
        label: 'SOA',
        target: queryTarget,
        resolve: async () => dns.resolveSoa(queryTarget)
      }
    ];

    for (const plan of plans) {
      try {
        const result = await plan.resolve();
        if (isEmptyResult(result)) {
          continue;
        }

        findings.push({
          findingId: createId('finding'),
          category: 'dns-record',
          title: `DNS ${plan.label} records for ${plan.target}`,
          description: `Public DNS resolution returned ${plan.label} data for ${plan.target}.`,
          target: plan.target,
          confidence: 'high',
          sourceTools: ['builtin-dns'],
          tags: ['dns', plan.label.toLowerCase()],
          evidence: {
            recordType: plan.label,
            target: plan.target,
            records: normalizeDnsResult(result)
          }
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (isExpectedDnsMiss(message)) {
          warnings.push({
            code: 'DNS_RECORD_ABSENT',
            message: `${plan.label} lookup for ${plan.target} returned no public record.`,
            severity: 'info',
            context: {
              recordType: plan.label,
              target: plan.target
            }
          });
          continue;
        }

        errors.push(`${plan.label} ${plan.target}: ${message}`);
      }
    }

    const finishedAt = new Date().toISOString();
    return {
      toolExecution: {
        toolId: 'builtin-dns',
        name: 'Built-in DNS Collector',
        mode: 'builtin',
        status: errors.length > 0 ? (findings.length > 0 ? 'partial' : 'failed') : 'completed',
        target: queryTarget,
        startedAt,
        finishedAt,
        outputCount: findings.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: errors.map((message) => ({
        code: 'DNS_COLLECTION_FAILED',
        message,
        recoverable: true
      }))
    };
  }
};

function normalizeDnsResult(result: unknown): JsonValue {
  if (Array.isArray(result)) {
    return result.map((entry) => normalizeDnsResult(entry));
  }

  if (typeof result === 'object' && result !== null) {
    return Object.fromEntries(
      Object.entries(result).map(([key, value]) => [key, normalizeDnsResult(value)])
    );
  }

  if (
    result === null ||
    typeof result === 'string' ||
    typeof result === 'number' ||
    typeof result === 'boolean'
  ) {
    return result;
  }

  return String(result);
}

function isExpectedDnsMiss(message: string): boolean {
  return ['ENODATA', 'ENOTFOUND', 'ESERVFAIL', 'ENOTIMP'].some((token) =>
    message.toUpperCase().includes(token.toUpperCase())
  );
}

function isEmptyResult(result: unknown): boolean {
  if (Array.isArray(result)) {
    return result.length === 0;
  }

  return result == null;
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
