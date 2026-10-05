import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import type { BlancheOsintSeedV1 } from '../../shared-schema/src';
import { dnsCollector } from './collectors/dnsCollector';
import { externalToolCollectors } from './collectors/externalToolCollector';
import { httpCollector } from './collectors/httpCollector';
import { tlsCollector } from './collectors/tlsCollector';
import type { CollectorDefinition } from './collectors/types';
import { buildOsintReport, renderReportMarkdown } from './report';
import { createManualSeed, extractRelatedHostnames, normalizeSeed } from './shared/targeting';

interface CliOptions {
  seedFile?: string;
  target?: string;
  outputDir?: string;
  timeoutMs: number;
  includeExternalTools: boolean;
}

const options = parseArgs(process.argv.slice(2));
if (!options.seedFile && !options.target) {
  printUsage();
  process.exitCode = 1;
} else {
  void run(options).catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}

async function run(options: CliOptions): Promise<void> {
  const seed = options.seedFile ? await loadSeed(options.seedFile) : createManualSeed(options.target ?? '');
  const normalized = normalizeSeed(seed);
  const relatedHostnames = extractRelatedHostnames(seed);

  const collectors: CollectorDefinition[] = [dnsCollector, httpCollector, tlsCollector];
  if (options.includeExternalTools) {
    collectors.push(...externalToolCollectors);
  }

  const outputs = await Promise.all(
    collectors.map((collector) =>
      collector.run({
        seed,
        primaryHostname: normalized.primaryHostname,
        apparentRootDomain: normalized.apparentRootDomain,
        relatedHostnames,
        timeoutMs: options.timeoutMs
      })
    )
  );

  const report = buildOsintReport({
    seed,
    outputs
  });

  if (options.outputDir) {
    await writeArtifacts(options.outputDir, report);
  }

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

async function loadSeed(seedFile: string): Promise<BlancheOsintSeedV1> {
  const raw = await fs.readFile(seedFile, 'utf8');
  const parsed = JSON.parse(raw) as Partial<BlancheOsintSeedV1>;
  if (parsed.kind !== 'blanche.osint-seed') {
    throw new Error(`Unsupported seed payload kind in ${seedFile}`);
  }
  if (!parsed.seed?.primaryHostname) {
    throw new Error(`Seed payload in ${seedFile} is missing seed.primaryHostname`);
  }
  return parsed as BlancheOsintSeedV1;
}

async function writeArtifacts(outputDir: string, report: ReturnType<typeof buildOsintReport>): Promise<void> {
  await fs.mkdir(outputDir, { recursive: true });
  const timestamp = report.reportMetadata.generatedAt.replaceAll(':', '-');
  const hostnameStem = report.target.primaryHostname.replaceAll(/[^a-z0-9.-]/gi, '_');
  const jsonPath = path.join(outputDir, `${hostnameStem}_${timestamp}.json`);
  const markdownPath = path.join(outputDir, `${hostnameStem}_${timestamp}.md`);
  await fs.writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  await fs.writeFile(markdownPath, renderReportMarkdown(report), 'utf8');
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    timeoutMs: 8000,
    includeExternalTools: true
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--seed-file':
        options.seedFile = argv[index + 1];
        index += 1;
        break;
      case '--target':
        options.target = argv[index + 1];
        index += 1;
        break;
      case '--output-dir':
        options.outputDir = argv[index + 1];
        index += 1;
        break;
      case '--timeout-ms':
        options.timeoutMs = Number(argv[index + 1] ?? options.timeoutMs);
        index += 1;
        break;
      case '--no-external-tools':
        options.includeExternalTools = false;
        break;
      case '--help':
        printUsage();
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${argument}`);
    }
  }

  return options;
}

function printUsage(): void {
  process.stdout.write(`BLANCHE OSINT Orchestrator

Usage:
  node osint-orchestrator/dist/cli.js --seed-file <path> [--output-dir <dir>] [--timeout-ms <ms>]
  node osint-orchestrator/dist/cli.js --target <hostname-or-url> [--output-dir <dir>] [--no-external-tools]
`);
}
