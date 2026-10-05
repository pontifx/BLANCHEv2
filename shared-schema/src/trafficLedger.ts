import type {
  BLANCHE_TRAFFIC_LEDGER_KIND,
  BLANCHE_TRAFFIC_LEDGER_SCHEMA_VERSION
} from './constants';
import type { ConfidenceLevel } from './types';

export type TrafficLedgerKind = typeof BLANCHE_TRAFFIC_LEDGER_KIND;
export type TrafficLedgerSchemaVersion = typeof BLANCHE_TRAFFIC_LEDGER_SCHEMA_VERSION;

export type TrafficScopeDisposition = 'in-scope' | 'out-of-scope' | 'review' | 'unknown';
export type TrafficScopeRuleDisposition = Exclude<TrafficScopeDisposition, 'unknown'>;
export type TrafficScopeRuleSource = 'operator' | 'burp' | 'capture-target' | 'imported';
export type TrafficPriorityBand = 'low' | 'medium' | 'high' | 'urgent';
export type TrafficScheme = 'http' | 'https' | 'ws' | 'wss';
export type TrafficObservationSource =
  | 'chromium-performance'
  | 'chromium-web-request'
  | 'chromium-instrumentation'
  | 'burp-proxy'
  | 'burp-site-map';
export type TrafficCacheState =
  | 'network'
  | 'memory-cache'
  | 'disk-cache'
  | 'service-worker'
  | 'unknown';
export type TrafficBoundary = 'same-origin' | 'same-site' | 'cross-site' | 'unknown';
export type TrafficOwnership =
  | 'target'
  | 'same-organization'
  | 'delegated'
  | 'third-party'
  | 'shared'
  | 'unknown';
export type TrafficEnvironment =
  | 'production'
  | 'staging'
  | 'development'
  | 'test'
  | 'local'
  | 'unknown';
export type TrafficRole =
  | 'navigation'
  | 'api'
  | 'authentication'
  | 'authorization'
  | 'administration'
  | 'configuration'
  | 'upload'
  | 'download'
  | 'realtime'
  | 'telemetry'
  | 'static'
  | 'worker'
  | 'client-control'
  | 'source-map'
  | 'other';
export type TrafficAccess =
  | 'anonymous'
  | 'authenticated'
  | 'privileged'
  | 'service'
  | 'unknown';
export type TrafficOperation =
  | 'read'
  | 'create'
  | 'update'
  | 'delete'
  | 'authenticate'
  | 'authorize'
  | 'upload'
  | 'download'
  | 'subscribe'
  | 'execute'
  | 'unknown';
export type TrafficDataClass =
  | 'credential'
  | 'session'
  | 'personal'
  | 'financial'
  | 'health'
  | 'internal'
  | 'source-code';

export type TrafficScopeRuleMatcherV1 =
  | {
      kind: 'exact-host';
      hostname: string;
      schemes?: TrafficScheme[];
      ports?: number[];
    }
  | {
      kind: 'wildcard-subdomain';
      baseHostname: string;
      schemes?: TrafficScheme[];
      ports?: number[];
    }
  | {
      kind: 'url-prefix';
      prefix: string;
    }
  | {
      kind: 'ipv4-cidr';
      cidr: string;
      schemes?: TrafficScheme[];
      ports?: number[];
    };

export interface TrafficScopeRuleV1 {
  ruleId: string;
  priority: number;
  disposition: TrafficScopeRuleDisposition;
  source: TrafficScopeRuleSource;
  matcher: TrafficScopeRuleMatcherV1;
  methods?: string[];
  note?: string;
}

export interface TrafficScopePolicyV1 {
  policyId: string;
  version: string;
  defaultDisposition: Exclude<TrafficScopeDisposition, 'in-scope'>;
  evaluation: 'highest-priority-exclude-on-tie';
  rules: TrafficScopeRuleV1[];
}

export interface TrafficScopeDecisionV1 {
  disposition: TrafficScopeDisposition;
  confidence: ConfidenceLevel;
  basis: 'matched-rule' | 'default' | 'operator-override' | 'burp-target-scope';
  policyId: string;
  policyVersion: string;
  matchedRuleIds: string[];
  reasonCodes: string[];
  evaluatedAt: string;
}

export interface TrafficEndpointV1 {
  scheme: TrafficScheme;
  host: string;
  registrableDomain?: string;
  port: number;
  method: string;
  pathTemplate: string;
  queryParameterNames: string[];
}

export interface TrafficObservationSummaryV1 {
  firstSeen: string;
  lastSeen: string;
  count: number;
  sources: TrafficObservationSource[];
  sourceOrigins: string[];
  frameIds: number[];
  initiatorTypes: string[];
  resourceTypes: string[];
  statusCodes: number[];
  contentTypes: string[];
  protocols: string[];
  cacheStates: TrafficCacheState[];
  requestHeaderNames: string[];
  responseHeaderNames: string[];
  requestBodyFieldNames: string[];
  coverageGaps: string[];
  bytes?: {
    transfer: number;
    encoded: number;
    decoded: number;
  };
}

export interface TrafficClassificationV1 {
  boundary: TrafficBoundary;
  ownership: TrafficOwnership;
  environment: TrafficEnvironment;
  roles: TrafficRole[];
  access: TrafficAccess;
  operations: TrafficOperation[];
  dataClasses: TrafficDataClass[];
  confidence: ConfidenceLevel;
  reasonCodes: string[];
}

export interface TrafficPriorityFactorV1 {
  code: string;
  delta: number;
  reason: string;
  evidenceRefs: string[];
}

export interface TrafficPriorityAssessmentV1 {
  score: number;
  band: TrafficPriorityBand;
  evidenceConfidence: ConfidenceLevel;
  classificationConfidence: ConfidenceLevel;
  factors: TrafficPriorityFactorV1[];
}

export interface TrafficEvidenceReferenceV1 {
  kind: 'artifact' | 'browser-request' | 'burp-message' | 'collector';
  id: string;
  source: string;
  observedAt?: string;
}

export interface TrafficLedgerEntryV1 {
  entryId: string;
  endpoint: TrafficEndpointV1;
  observation: TrafficObservationSummaryV1;
  scope: TrafficScopeDecisionV1;
  classification: TrafficClassificationV1;
  priority: TrafficPriorityAssessmentV1;
  evidence: TrafficEvidenceReferenceV1[];
}

export interface TrafficLedgerSummaryV1 {
  entryCount: number;
  byScope: Record<TrafficScopeDisposition, number>;
  byPriority: Record<TrafficPriorityBand, number>;
  handoffEligibleCount: number;
  highestScore: number;
}

export interface BlancheTrafficLedgerV1 {
  kind: TrafficLedgerKind;
  schemaVersion: TrafficLedgerSchemaVersion;
  metadata: {
    ledgerId: string;
    generatedAt: string;
    sourceSessionId: string;
    targetOrigin?: string;
    observationWindowStart?: string;
    observationWindowBasis?: 'retained-last-seen';
    identityModel: 'blanche.endpoint-sha256.v1';
    scoreModel: 'blanche.traffic-priority.v1';
    captureCoverage?: {
      retainedEntryLimit: number;
      persistedByteLimit: number;
      droppedEntryCount: number;
      retentionLossScope: 'store-wide-conservative';
      availableEntryCount: number;
      exportedEntryCount: number;
      truncated: boolean;
      reasonCodes: string[];
    };
  };
  scopePolicy: TrafficScopePolicyV1;
  entries: TrafficLedgerEntryV1[];
  summary: TrafficLedgerSummaryV1;
  dataHandling: {
    queryValuesIncluded: false;
    fragmentsIncluded: false;
    userinfoIncluded: false;
    pathHandling: {
      model: 'blanche.path-template.v1';
      recognizedIdentifiersTemplated: true;
      unrecognizedPathSegmentsIncluded: true;
      residualIdentifierRisk: true;
    };
    rawEvidenceOutsideLedger: true;
  };
}

export type ScopePolicy = TrafficScopePolicyV1;
export type ScopeDecision = TrafficScopeDecisionV1;
export type TrafficLedgerEntry = TrafficLedgerEntryV1;
export type TrafficLedgerSummary = TrafficLedgerSummaryV1;
