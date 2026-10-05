import { spawn } from 'node:child_process';
import type { ExportWarning, OsintFinding } from '../../../shared-schema/src';
import { deriveApparentRootDomain, normalizeHostname } from '../shared/targeting';
import type { CollectorDefinition, CollectorRunOutput } from './types';

interface ExternalToolSpec {
  id: string;
  name: string;
  command: string;
  buildArgs(target: string): string[];
  parse(lines: string[]): {
    category: OsintFinding['category'];
    title: string;
    description: string;
    tags: string[];
    evidenceKey: string;
    values: string[];
  };
}

const EXTERNAL_TOOL_SPECS: ExternalToolSpec[] = [
  {
    id: 'subfinder',
    name: 'subfinder',
    command: 'subfinder',
    buildArgs: (target) => ['-silent', '-d', target],
    parse: (lines) => ({
      category: 'hostname',
      title: 'Passive subdomain enumeration via subfinder',
      description: 'subfinder returned public hostnames that can expand the testing map.',
      tags: ['osint', 'subdomain', 'subfinder'],
      evidenceKey: 'hostnames',
      values: normalizeHostnameLines(lines)
    })
  },
  {
    id: 'assetfinder',
    name: 'assetfinder',
    command: 'assetfinder',
    buildArgs: (target) => ['--subs-only', target],
    parse: (lines) => ({
      category: 'hostname',
      title: 'Passive subdomain enumeration via assetfinder',
      description: 'assetfinder returned public hostnames that can expand the testing map.',
      tags: ['osint', 'subdomain', 'assetfinder'],
      evidenceKey: 'hostnames',
      values: normalizeHostnameLines(lines)
    })
  },
  {
    id: 'amass-passive',
    name: 'amass',
    command: 'amass',
    buildArgs: (target) => ['enum', '-passive', '-norecursive', '-noalts', '-d', target],
    parse: (lines) => ({
      category: 'hostname',
      title: 'Passive enumeration via amass',
      description: 'amass passive mode returned public hostnames that can expand the testing map.',
      tags: ['osint', 'subdomain', 'amass'],
      evidenceKey: 'hostnames',
      values: normalizeHostnameLines(lines)
    })
  },
  {
    id: 'gau',
    name: 'gau',
    command: 'gau',
    buildArgs: (target) => ['--subs', target],
    parse: (lines) => ({
      category: 'archive-reference',
      title: 'Historical URL references via gau',
      description: 'gau returned archived or indexed URLs that may help prioritize follow-on review.',
      tags: ['osint', 'archive', 'gau'],
      evidenceKey: 'urls',
      values: normalizeUrlLines(lines)
    })
  },
  {
    id: 'waybackurls',
    name: 'waybackurls',
    command: 'waybackurls',
    buildArgs: (target) => [target],
    parse: (lines) => ({
      category: 'archive-reference',
      title: 'Historical URL references via waybackurls',
      description: 'waybackurls returned archived URLs that may help prioritize follow-on review.',
      tags: ['osint', 'archive', 'wayback'],
      evidenceKey: 'urls',
      values: normalizeUrlLines(lines)
    })
  }
];

export const externalToolCollectors: CollectorDefinition[] = EXTERNAL_TOOL_SPECS.map((spec) => ({
  id: `external-${spec.id}`,
  name: `External Tool: ${spec.name}`,
  async run(context): Promise<CollectorRunOutput> {
    const startedAt = new Date().toISOString();
    const warnings: ExportWarning[] = [];
    const target =
      context.apparentRootDomain ??
      deriveApparentRootDomain(context.primaryHostname) ??
      context.primaryHostname;
    const args = spec.buildArgs(target);
    const commandLabel = [spec.command, ...args].join(' ');

    const processResult = await runProcess(spec.command, args, context.timeoutMs);
    if (processResult.status === 'missing') {
      const message = `${spec.command} was not found on PATH; the collector was skipped.`;
      return {
        toolExecution: {
          toolId: spec.id,
          name: spec.name,
          mode: 'external',
          status: 'skipped',
          target,
          startedAt,
          finishedAt: new Date().toISOString(),
          command: commandLabel,
          outputCount: 0,
          warnings: [message],
          errors: []
        },
        findings: [],
        warnings: [
          {
            code: 'EXTERNAL_TOOL_MISSING',
            message,
            severity: 'info',
            context: {
              toolId: spec.id
            }
          }
        ],
        errors: []
      };
    }

    const parsed = spec.parse(processResult.stdout.split(/\r?\n/).filter(Boolean));
    const finishedAt = new Date().toISOString();
    const findings: OsintFinding[] =
      parsed.values.length > 0
        ? [
            {
              findingId: createId('finding'),
              category: parsed.category,
              title: parsed.title,
              description: parsed.description,
              target,
              confidence: 'medium',
              sourceTools: [spec.id],
              tags: parsed.tags,
              evidence: {
                [parsed.evidenceKey]: parsed.values.slice(0, 500),
                lineCount: parsed.values.length,
                command: commandLabel
              }
            }
          ]
        : [];

    if (processResult.stderr.trim()) {
      warnings.push({
        code: 'EXTERNAL_TOOL_STDERR',
        message: `${spec.command} emitted stderr output during passive collection.`,
        severity: 'info',
        context: {
          toolId: spec.id,
          stderr: processResult.stderr.slice(0, 800)
        }
      });
    }

    const errors = processResult.status === 'failed' ? [processResult.errorMessage] : [];
    return {
      toolExecution: {
        toolId: spec.id,
        name: spec.name,
        mode: 'external',
        status:
          processResult.status === 'failed'
            ? findings.length > 0
              ? 'partial'
              : 'failed'
            : 'completed',
        target,
        startedAt,
        finishedAt,
        command: commandLabel,
        outputCount: parsed.values.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: errors.map((message) => ({
        code: 'EXTERNAL_TOOL_FAILED',
        message,
        recoverable: true,
        context: {
          toolId: spec.id
        }
      }))
    };
  }
}));

type ProcessRunResult =
  | {
      status: 'completed';
      stdout: string;
      stderr: string;
      errorMessage: '';
    }
  | {
      status: 'failed';
      stdout: string;
      stderr: string;
      errorMessage: string;
    }
  | {
      status: 'missing';
      stdout: '';
      stderr: '';
      errorMessage: '';
    };

function runProcess(command: string, args: string[], timeoutMs: number): Promise<ProcessRunResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill();
        resolve({
          status: 'failed',
          stdout,
          stderr,
          errorMessage: `timed out after ${timeoutMs}ms`
        });
      }
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('error', (error) => {
      clearTimeout(timeout);
      if (settled) {
        return;
      }
      settled = true;
      if ('code' in error && error.code === 'ENOENT') {
        resolve({
          status: 'missing',
          stdout: '',
          stderr: '',
          errorMessage: ''
        });
        return;
      }

      resolve({
        status: 'failed',
        stdout,
        stderr,
        errorMessage: error.message
      });
    });
    child.on('close', (code) => {
      clearTimeout(timeout);
      if (settled) {
        return;
      }
      settled = true;
      if (code == 0) {
        resolve({
          status: 'completed',
          stdout,
          stderr,
          errorMessage: ''
        });
        return;
      }

      resolve({
        status: 'failed',
        stdout,
        stderr,
        errorMessage: `exited with code ${code ?? 'unknown'}`
      });
    });
  });
}

function normalizeHostnameLines(lines: string[]): string[] {
  const hostnames = new Set<string>();
  for (const line of lines) {
    const normalized = normalizeHostname(line);
    if (normalized) {
      hostnames.add(normalized);
    }
  }
  return [...hostnames].sort();
}

function normalizeUrlLines(lines: string[]): string[] {
  const urls = new Set<string>();
  for (const line of lines) {
    const value = line.trim();
    if (!value) {
      continue;
    }

    try {
      urls.add(new URL(value).toString());
    } catch {
      continue;
    }
  }
  return [...urls].sort();
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
