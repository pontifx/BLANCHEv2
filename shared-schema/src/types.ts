import type { BLANCHE_EXPORT_KIND, BLANCHE_SCHEMA_VERSION } from './constants';
import type { BlancheTrafficLedgerV1 } from './trafficLedger';

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;

export interface JsonArray extends Array<JsonValue> {}

export interface JsonObject {
  [key: string]: JsonValue;
}

export type ExportKind = typeof BLANCHE_EXPORT_KIND;
export type SchemaVersion = typeof BLANCHE_SCHEMA_VERSION;
export type CollectionMode = 'passive' | 'instrumented';
export type CollectorStatus = 'ok' | 'partial' | 'error';
export type ProvenanceDisposition = 'observed' | 'inferred' | 'unavailable';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type ArtifactCategory =
  | 'document'
  | 'frame'
  | 'resource'
  | 'script'
  | 'stylesheet'
  | 'image'
  | 'font'
  | 'manifest'
  | 'iframe'
  | 'worker'
  | 'service-worker'
  | 'blob'
  | 'data-url'
  | 'storage-key'
  | 'indexeddb-database'
  | 'cache'
  | 'runtime-indicator'
  | 'unknown';

export interface ExportMetadata {
  exportId: string;
  exportedAt: string;
  generatedBy: {
    product: 'BLANCHE';
    component: string;
    version: string;
    moduleId: string;
    moduleVersion: string;
  };
}

export interface ModuleReference {
  id: string;
  name: string;
  version: string;
}

export interface TabMetadata {
  tabId: number;
  windowId?: number;
  openerTabId?: number;
  status?: string;
  active?: boolean;
  discarded?: boolean;
  audible?: boolean;
  favIconUrl?: string;
}

export interface FrameMetadata {
  frameId: number;
  parentFrameId?: number;
  url?: string;
  origin?: string;
  documentId?: string;
  transitionType?: string;
  frameType?: string;
  errorOccurred?: boolean;
}

export interface PageMetadata {
  url?: string;
  title?: string;
  origin?: string;
  referrer?: string;
  topLevelFrameId?: number;
  frames: FrameMetadata[];
  tab: TabMetadata;
}

export interface ExportWarning {
  code: string;
  message: string;
  collectorId?: string;
  severity: 'info' | 'warning';
  context?: JsonObject;
}

export interface ExportError {
  code: string;
  message: string;
  collectorId?: string;
  recoverable: boolean;
  context?: JsonObject;
}

export interface VisibilityGap {
  code: string;
  surface: 'background' | 'content' | 'page' | 'devtools' | 'sidepanel';
  message: string;
  reason:
    | 'cross-origin'
    | 'permission'
    | 'api-unavailable'
    | 'timing'
    | 'unsupported-context'
    | 'implementation-gap';
  context?: JsonObject;
}

export interface ProvenanceDescriptor {
  disposition: ProvenanceDisposition;
  confidence: ConfidenceLevel;
  sources: string[];
  note?: string;
}

export interface ArtifactDescriptor {
  artifactId: string;
  category: ArtifactCategory;
  kind: string;
  url?: string;
  frameId?: number;
  origin?: string;
  discoveredBy: string[];
  attributes: JsonObject;
  provenance: ProvenanceDescriptor;
}

export interface PermissionsState {
  grantedPermissions: string[];
  grantedHostPermissions: string[];
  moduleRequirements: Array<{
    moduleId: string;
    requiredPermissions: string[];
    requiredHostPermissions: string[];
  }>;
}

export interface CollectionMetadata {
  sessionId: string;
  mode: CollectionMode;
  reloadTriggered: boolean;
  startedAt: string;
  finishedAt: string;
  target: {
    tabId: number;
    initialUrl?: string;
    finalUrl?: string;
  };
}

export interface CollectorResult<TData extends JsonValue | JsonObject = JsonObject> {
  collectorId: string;
  name: string;
  surface: 'background' | 'content' | 'page';
  status: CollectorStatus;
  collectedAt: string;
  warnings: ExportWarning[];
  errors: ExportError[];
  visibilityGaps: VisibilityGap[];
  data: TData;
}

export interface ExportSummary {
  artifactCount: number;
  artifactCountsByCategory: Record<string, number>;
  warningCount: number;
  errorCount: number;
  visibilityGapCount: number;
}

export interface BlancheExportV1 {
  kind: ExportKind;
  schemaVersion: SchemaVersion;
  exportMetadata: ExportMetadata;
  module: ModuleReference;
  page: PageMetadata;
  collection: CollectionMetadata;
  permissions: PermissionsState;
  collectors: CollectorResult[];
  artifacts: ArtifactDescriptor[];
  trafficLedger: BlancheTrafficLedgerV1;
  warnings: ExportWarning[];
  errors: ExportError[];
  visibilityGaps: VisibilityGap[];
  summary: ExportSummary;
}
