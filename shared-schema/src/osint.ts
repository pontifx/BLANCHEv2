import type {
  BLANCHE_OSINT_REPORT_KIND,
  BLANCHE_OSINT_SCHEMA_VERSION,
  BLANCHE_OSINT_SEED_KIND
} from './constants';
import type { ConfidenceLevel, ExportError, ExportWarning, JsonObject } from './types';

export type OsintSchemaVersion = typeof BLANCHE_OSINT_SCHEMA_VERSION;
export type OsintSeedKind = typeof BLANCHE_OSINT_SEED_KIND;
export type OsintReportKind = typeof BLANCHE_OSINT_REPORT_KIND;

export type OsintCollectionMode = 'public-passive' | 'public-minimal-touch';
export type OsintSeedSourceType =
  | 'tab-url'
  | 'dom-link'
  | 'dom-script'
  | 'dom-image'
  | 'dom-stylesheet'
  | 'dom-form'
  | 'dom-iframe'
  | 'manifest'
  | 'browser-export'
  | 'manual';
export type OsintToolMode = 'builtin' | 'external';
export type OsintToolStatus = 'completed' | 'partial' | 'skipped' | 'failed';
export type OsintFindingCategory =
  | 'domain'
  | 'hostname'
  | 'dns-record'
  | 'http-surface'
  | 'security-contact'
  | 'tls-certificate'
  | 'archive-reference'
  | 'third-party-service'
  | 'technology-hint'
  | 'document-reference'
  | 'scope-note';

export interface OsintGeneratedBy {
  product: 'BLANCHE';
  component: string;
  version: string;
  moduleId?: string;
  moduleVersion?: string;
}

export interface OsintScopeStatement {
  mode: OsintCollectionMode;
  allowedActivities: string[];
  disallowedActivities: string[];
  operatorNotes?: string[];
}

export interface OsintSeedObservation {
  hostname: string;
  url?: string;
  sourceType: OsintSeedSourceType;
  confidence: ConfidenceLevel;
  note?: string;
}

export interface OsintSeedContext {
  tabId?: number;
  pageUrl?: string;
  pageOrigin?: string;
  pageTitle?: string;
  referrer?: string;
  apparentRootDomain?: string;
  relatedHosts: OsintSeedObservation[];
  signals: JsonObject;
}

export interface BlancheOsintSeedV1 {
  kind: OsintSeedKind;
  schemaVersion: OsintSchemaVersion;
  seedMetadata: {
    seedId: string;
    createdAt: string;
    generatedBy: OsintGeneratedBy;
  };
  scope: OsintScopeStatement;
  seed: {
    targetUrl?: string;
    targetOrigin?: string;
    primaryHostname: string;
    apparentRootDomain?: string;
    sourceType: OsintSeedSourceType;
  };
  browserContext: OsintSeedContext;
  warnings: ExportWarning[];
}

export interface OsintToolExecution {
  toolId: string;
  name: string;
  mode: OsintToolMode;
  status: OsintToolStatus;
  target: string;
  startedAt: string;
  finishedAt: string;
  command?: string;
  outputCount: number;
  warnings: string[];
  errors: string[];
}

export interface OsintFinding {
  findingId: string;
  category: OsintFindingCategory;
  title: string;
  description: string;
  target: string;
  confidence: ConfidenceLevel;
  sourceTools: string[];
  tags: string[];
  evidence: JsonObject;
}

export interface OsintNarrative {
  headline: string;
  summary: string;
  followOnFocus: string[];
  reportReadyNotes: string[];
}

export interface BlancheOsintReportV1 {
  kind: OsintReportKind;
  schemaVersion: OsintSchemaVersion;
  reportMetadata: {
    reportId: string;
    generatedAt: string;
    generatedBy: OsintGeneratedBy;
    seedId?: string;
  };
  scope: OsintScopeStatement;
  target: {
    primaryHostname: string;
    apparentRootDomain?: string;
    targetUrl?: string;
    targetOrigin?: string;
    relatedHostnames: string[];
  };
  seed?: BlancheOsintSeedV1;
  toolExecutions: OsintToolExecution[];
  findings: OsintFinding[];
  warnings: ExportWarning[];
  errors: ExportError[];
  narrative: OsintNarrative;
  summary: {
    findingCount: number;
    findingsByCategory: Record<string, number>;
    completedTools: number;
    skippedTools: number;
    failedTools: number;
  };
}
