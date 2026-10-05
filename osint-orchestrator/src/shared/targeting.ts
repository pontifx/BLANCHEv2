import {
  BLANCHE_OSINT_SCHEMA_VERSION,
  BLANCHE_OSINT_SEED_KIND,
  type BlancheOsintSeedV1,
  type OsintSeedObservation,
  type OsintSeedSourceType
} from '../../../shared-schema/src';
import { createDefaultScopeStatement } from './guardrails';

export interface NormalizedTarget {
  primaryHostname: string;
  apparentRootDomain?: string;
  targetUrl?: string;
  targetOrigin?: string;
}

export function normalizeHostname(rawValue: string | undefined): string | undefined {
  if (!rawValue) {
    return undefined;
  }

  const normalized = rawValue.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized || /\s/.test(normalized)) {
    return undefined;
  }

  return normalized;
}

export function deriveApparentRootDomain(hostname: string | undefined): string | undefined {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return undefined;
  }

  const labels = normalized.split('.');
  if (labels.length <= 2) {
    return normalized;
  }

  const tld = labels.at(-1) ?? '';
  const secondLevel = labels.at(-2) ?? '';
  const commonCountryCodeSecondLevels = new Set(['co', 'com', 'org', 'net', 'gov', 'edu']);
  if (tld.length === 2 && commonCountryCodeSecondLevels.has(secondLevel) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }

  return labels.slice(-2).join('.');
}

export function normalizeSeed(seed: BlancheOsintSeedV1): NormalizedTarget {
  return {
    primaryHostname: seed.seed.primaryHostname,
    apparentRootDomain: seed.seed.apparentRootDomain,
    targetUrl: seed.seed.targetUrl,
    targetOrigin: seed.seed.targetOrigin
  };
}

export function extractRelatedHostnames(seed: BlancheOsintSeedV1): string[] {
  const hostnames = new Set<string>();
  for (const relatedHost of seed.browserContext.relatedHosts) {
    const normalized = normalizeHostname(relatedHost.hostname);
    if (normalized) {
      hostnames.add(normalized);
    }
  }

  return [...hostnames].sort();
}

export function createManualSeed(rawTarget: string): BlancheOsintSeedV1 {
  const targetUrl = ensureUrl(rawTarget);
  const parsed = new URL(targetUrl);
  const primaryHostname = normalizeHostname(parsed.hostname);
  if (!primaryHostname) {
    throw new Error(`Unable to derive a hostname from target ${rawTarget}`);
  }

  return {
    kind: BLANCHE_OSINT_SEED_KIND,
    schemaVersion: BLANCHE_OSINT_SCHEMA_VERSION,
    seedMetadata: {
      seedId: createId('seed'),
      createdAt: new Date().toISOString(),
      generatedBy: {
        product: 'BLANCHE',
        component: 'osint-orchestrator/cli',
        version: '0.1.0'
      }
    },
    scope: createDefaultScopeStatement(),
    seed: {
      targetUrl,
      targetOrigin: parsed.origin,
      primaryHostname,
      apparentRootDomain: deriveApparentRootDomain(primaryHostname),
      sourceType: 'manual'
    },
    browserContext: {
      pageUrl: targetUrl,
      pageOrigin: parsed.origin,
      apparentRootDomain: deriveApparentRootDomain(primaryHostname),
      relatedHosts: [],
      signals: {}
    },
    warnings: [
      {
        code: 'MANUAL_SEED_CREATED',
        message: 'The OSINT run used a manually provided target instead of a Chromium-derived seed.',
        severity: 'info'
      }
    ]
  };
}

export function createSeedObservation(
  hostname: string,
  sourceType: OsintSeedSourceType,
  input: {
    url?: string;
    confidence?: OsintSeedObservation['confidence'];
    note?: string;
  } = {}
): OsintSeedObservation {
  return {
    hostname,
    sourceType,
    confidence: input.confidence ?? 'medium',
    url: input.url,
    note: input.note
  };
}

export function ensureUrl(rawTarget: string): string {
  if (/^[a-z]+:\/\//i.test(rawTarget)) {
    return rawTarget;
  }

  return `https://${rawTarget}`;
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
