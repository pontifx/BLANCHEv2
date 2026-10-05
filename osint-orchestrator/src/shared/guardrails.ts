import type { OsintScopeStatement } from '../../../shared-schema/src';

const ALLOWED_ACTIVITIES = [
  'Resolve public DNS records for in-scope hosts.',
  'Fetch public web resources such as /, robots.txt, sitemap.xml, and /.well-known/security.txt.',
  'Inspect public TLS certificate metadata presented by the target host.',
  'Run approved passive OSINT tools with non-intrusive discovery flags only.'
] as const;

const DISALLOWED_ACTIVITIES = [
  'Do not authenticate, brute force, fuzz, exploit, scan ports broadly, or validate vulnerabilities.',
  'Do not collect non-public information or bypass access controls.',
  'Do not assign severity or represent informational OSINT as validated findings.',
  'Do not replace existing ProdPT testing workflows; this output is preparatory context.'
] as const;

export function createDefaultScopeStatement(): OsintScopeStatement {
  return {
    mode: 'public-passive',
    allowedActivities: [...ALLOWED_ACTIVITIES],
    disallowedActivities: [...DISALLOWED_ACTIVITIES],
    operatorNotes: [
      'Outputs are informational and intended to guide follow-on testing, not validate security impact.'
    ]
  };
}
