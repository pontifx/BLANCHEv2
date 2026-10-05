import type {
  BlancheOsintSeedV1,
  ExportError,
  ExportWarning,
  OsintFinding,
  OsintToolExecution
} from '../../../shared-schema/src';

export interface CollectorContext {
  seed: BlancheOsintSeedV1;
  primaryHostname: string;
  apparentRootDomain?: string;
  relatedHostnames: string[];
  timeoutMs: number;
}

export interface CollectorRunOutput {
  toolExecution: OsintToolExecution;
  findings: OsintFinding[];
  warnings: ExportWarning[];
  errors: ExportError[];
}

export interface CollectorDefinition {
  id: string;
  name: string;
  run(context: CollectorContext): Promise<CollectorRunOutput>;
}
