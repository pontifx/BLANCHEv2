import type {
  BLANCHE_TEAR_SHEET_KIND,
  BLANCHE_TEAR_SHEET_SCHEMA_VERSION
} from './constants';
import type {
  ArtifactCategory,
  BlancheExportV1,
  CollectionMode,
  CollectorStatus,
  ConfidenceLevel,
  JsonObject,
  JsonPrimitive,
  PermissionsState,
  ProvenanceDisposition
} from './types';

export type TearSheetKind = typeof BLANCHE_TEAR_SHEET_KIND;
export type TearSheetSchemaVersion = typeof BLANCHE_TEAR_SHEET_SCHEMA_VERSION;
export type TearSheetAssessment = 'healthy' | 'limited' | 'degraded';
export type TearSheetObservationTone = 'neutral' | 'attention';

export interface TearSheetMetric {
  id: string;
  label: string;
  value: JsonPrimitive;
  detail: string;
}

export interface TearSheetCollectorCoverage {
  collectorId: string;
  name: string;
  surface: 'background' | 'content' | 'page';
  status: CollectorStatus;
  collectedAt: string;
  warningCount: number;
  errorCount: number;
  visibilityGapCount: number;
}

export interface TearSheetArtifactExample {
  artifactId: string;
  kind: string;
  url?: string;
  origin?: string;
  frameId?: number;
  disposition: ProvenanceDisposition;
  confidence: ConfidenceLevel;
  discoveredBy: string[];
}

export interface TearSheetArtifactCategorySummary {
  category: ArtifactCategory;
  label: string;
  count: number;
  provenance: {
    observed: number;
    inferred: number;
    unavailable: number;
  };
  examples: TearSheetArtifactExample[];
}

export interface TearSheetOriginSummary {
  origin: string;
  count: number;
  crossOrigin: boolean;
  categories: ArtifactCategory[];
}

export interface TearSheetEvidenceReference {
  source:
    | 'artifact'
    | 'finding'
    | 'search'
    | 'document'
    | 'javascript'
    | 'latent-feature'
    | 'activity';
  id: string;
}

export interface TearSheetObservation {
  id: string;
  title: string;
  summary: string;
  whyItMatters: string;
  tone: TearSheetObservationTone;
  evidenceReferences: TearSheetEvidenceReference[];
}

export interface TearSheetLimitation {
  code: string;
  title: string;
  detail: string;
  source: 'warning' | 'error' | 'visibility-gap' | 'methodology';
}

export interface TearSheetCorrelatedEvidence {
  findings: JsonObject[];
  testerQuestions: JsonObject[];
  searchSessions: JsonObject[];
  documents: JsonObject[];
  latentFeatureScan?: JsonObject;
  javascriptTest?: JsonObject;
  interestAnalysis?: JsonObject;
  activity: JsonObject[];
}

export interface BlancheTearSheetV1 {
  kind: TearSheetKind;
  schemaVersion: TearSheetSchemaVersion;
  metadata: {
    reportId: string;
    generatedAt: string;
    evidenceAsOf: string;
    sourceExportId: string;
    generatedBy: {
      product: 'BLANCHE';
      component: string;
      version: string;
    };
  };
  target: {
    url?: string;
    title?: string;
    origin?: string;
    hostname?: string;
  };
  executiveSummary: {
    headline: string;
    overview: string;
    assessment: TearSheetAssessment;
    confidence: ConfidenceLevel;
    metrics: TearSheetMetric[];
  };
  captureProfile: {
    mode: CollectionMode;
    reloadTriggered: boolean;
    startedAt: string;
    finishedAt: string;
    durationMs?: number;
    frameCount: number;
    collectors: TearSheetCollectorCoverage[];
    permissions: PermissionsState;
  };
  evidenceSummary: {
    artifactCount: number;
    browserOnlyArtifactCount: number;
    crossOriginArtifactCount: number;
    uniqueOriginCount: number;
    provenance: {
      observed: number;
      inferred: number;
      unavailable: number;
    };
    categories: TearSheetArtifactCategorySummary[];
    origins: TearSheetOriginSummary[];
  };
  observations: TearSheetObservation[];
  limitations: TearSheetLimitation[];
  correlatedEvidence: TearSheetCorrelatedEvidence;
  dataHandling: {
    classification: 'assessment-sensitive';
    stakeholderViewRedactsRawValues: true;
    jsonContainsFullEvidence: true;
    notice: string;
  };
  sourceCapture: BlancheExportV1;
}
