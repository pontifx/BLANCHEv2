import type { ExportWarning, OsintFinding } from '../../../shared-schema/src';
import type { CollectorDefinition, CollectorRunOutput } from './types';

interface FetchResult {
  url: string;
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  body: string;
}

export const httpCollector: CollectorDefinition = {
  id: 'builtin-http',
  name: 'Built-in HTTP Surface Collector',
  async run(context): Promise<CollectorRunOutput> {
    const startedAt = new Date().toISOString();
    const warnings: ExportWarning[] = [];
    const findings: OsintFinding[] = [];
    const errors: string[] = [];

    const baseCandidates = [`https://${context.primaryHostname}`, `http://${context.primaryHostname}`];
    const homepage = await firstSuccessfulFetch(baseCandidates, '/', context.timeoutMs);
    if (homepage) {
      findings.push(buildHomepageFinding(homepage));

      const techEvidence = extractTechnologyEvidence(homepage);
      if (Object.keys(techEvidence).length > 0) {
        findings.push({
          findingId: createId('finding'),
          category: 'technology-hint',
          title: `Public technology hints for ${context.primaryHostname}`,
          description:
            'The public landing page exposed response headers or HTML metadata that can guide follow-on review.',
          target: context.primaryHostname,
          confidence: 'medium',
          sourceTools: ['builtin-http'],
          tags: ['http', 'technology'],
          evidence: techEvidence
        });
      }
    } else {
      warnings.push({
        code: 'HTTP_HOMEPAGE_UNREACHABLE',
        message: `The collector could not retrieve a public homepage for ${context.primaryHostname}.`,
        severity: 'warning'
      });
    }

    const probeBase = homepage?.url.replace(/\/$/, '') ?? `https://${context.primaryHostname}`;
    const robots = await fetchText(`${probeBase}/robots.txt`, context.timeoutMs);
    if (robots.ok) {
      findings.push(buildRobotsFinding(context.primaryHostname, robots));
    } else {
      warnings.push({
        code: 'ROBOTS_UNAVAILABLE',
        message: `robots.txt was not publicly available at ${probeBase}/robots.txt.`,
        severity: 'info'
      });
    }

    const securityTxt = await fetchText(`${probeBase}/.well-known/security.txt`, context.timeoutMs);
    if (securityTxt.ok) {
      findings.push(buildSecurityTxtFinding(context.primaryHostname, securityTxt));
    } else {
      warnings.push({
        code: 'SECURITY_TXT_UNAVAILABLE',
        message: `security.txt was not publicly available at ${probeBase}/.well-known/security.txt.`,
        severity: 'info'
      });
    }

    const sitemap = await fetchText(`${probeBase}/sitemap.xml`, context.timeoutMs);
    if (sitemap.ok) {
      findings.push({
        findingId: createId('finding'),
        category: 'document-reference',
        title: `Public sitemap reference for ${context.primaryHostname}`,
        description: 'A public sitemap was discoverable and can be used to widen page-level OSINT review.',
        target: context.primaryHostname,
        confidence: 'high',
        sourceTools: ['builtin-http'],
        tags: ['http', 'sitemap'],
        evidence: {
          url: sitemap.url,
          status: sitemap.status,
          snippet: sitemap.body.slice(0, 1200)
        }
      });
    }

    const finishedAt = new Date().toISOString();
    return {
      toolExecution: {
        toolId: 'builtin-http',
        name: 'Built-in HTTP Surface Collector',
        mode: 'builtin',
        status: errors.length > 0 ? (findings.length > 0 ? 'partial' : 'failed') : 'completed',
        target: context.primaryHostname,
        startedAt,
        finishedAt,
        outputCount: findings.length,
        warnings: warnings.map((warning) => warning.message),
        errors
      },
      findings,
      warnings,
      errors: errors.map((message) => ({
        code: 'HTTP_COLLECTION_FAILED',
        message,
        recoverable: true
      }))
    };
  }
};

async function firstSuccessfulFetch(
  baseUrls: string[],
  path: string,
  timeoutMs: number
): Promise<FetchResult | undefined> {
  for (const baseUrl of baseUrls) {
    const result = await fetchText(`${baseUrl}${path}`, timeoutMs);
    if (result.ok) {
      return result;
    }
  }

  return undefined;
}

async function fetchText(url: string, timeoutMs: number): Promise<FetchResult> {
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        'user-agent': 'BLANCHE-OSINT/0.1.0'
      }
    });

    const body = await response.text();
    return {
      url: response.url,
      ok: response.ok,
      status: response.status,
      headers: collectHeaders(response.headers),
      body: body.slice(0, 100_000)
    };
  } catch {
    return {
      url,
      ok: false,
      status: 0,
      headers: {},
      body: ''
    };
  }
}

function buildHomepageFinding(result: FetchResult): OsintFinding {
  return {
    findingId: createId('finding'),
    category: 'http-surface',
    title: `Public web surface for ${result.url}`,
    description: 'The target returned a public web response that can guide scope familiarization.',
    target: result.url,
    confidence: 'high',
    sourceTools: ['builtin-http'],
    tags: ['http', 'headers'],
    evidence: {
      status: result.status,
      headers: result.headers,
      title: extractHtmlTitle(result.body) ?? null,
      manifestHref: extractManifestHref(result.body) ?? null
    }
  };
}

function buildRobotsFinding(hostname: string, result: FetchResult): OsintFinding {
  const sitemapLines = result.body
    .split(/\r?\n/)
    .filter((line) => /^sitemap:/i.test(line))
    .slice(0, 15);
  const disallowCount = result.body
    .split(/\r?\n/)
    .filter((line) => /^disallow:/i.test(line)).length;

  return {
    findingId: createId('finding'),
    category: 'document-reference',
    title: `robots.txt observations for ${hostname}`,
    description: 'Public crawler policy and referenced sitemap hints were collected from robots.txt.',
    target: hostname,
    confidence: 'high',
    sourceTools: ['builtin-http'],
    tags: ['http', 'robots'],
    evidence: {
      url: result.url,
      status: result.status,
      disallowCount,
      sitemapReferences: sitemapLines
    }
  };
}

function buildSecurityTxtFinding(hostname: string, result: FetchResult): OsintFinding {
  const contacts = extractSecurityTxtValues(result.body, 'contact');
  const policies = extractSecurityTxtValues(result.body, 'policy');
  const acknowledgments = extractSecurityTxtValues(result.body, 'acknowledgments');

  return {
    findingId: createId('finding'),
    category: 'security-contact',
    title: `security.txt contacts for ${hostname}`,
    description: 'Public security contact metadata was exposed through a security.txt file.',
    target: hostname,
    confidence: 'high',
    sourceTools: ['builtin-http'],
    tags: ['http', 'security-txt'],
    evidence: {
      url: result.url,
      status: result.status,
      contacts,
      policies,
      acknowledgments
    }
  };
}

function extractSecurityTxtValues(body: string, key: string): string[] {
  return body
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.toLowerCase().startsWith(`${key.toLowerCase()}:`))
    .map((line) => line.split(':').slice(1).join(':').trim())
    .filter(Boolean);
}

function extractTechnologyEvidence(result: FetchResult): Record<string, string> {
  const evidence: Record<string, string> = {};
  const server = result.headers.server;
  const poweredBy = result.headers['x-powered-by'];
  const csp = result.headers['content-security-policy'];
  const hsts = result.headers['strict-transport-security'];
  const manifestHref = extractManifestHref(result.body);

  if (server) {
    evidence.server = server;
  }
  if (poweredBy) {
    evidence.xPoweredBy = poweredBy;
  }
  if (csp) {
    evidence.contentSecurityPolicy = csp;
  }
  if (hsts) {
    evidence.strictTransportSecurity = hsts;
  }
  if (manifestHref) {
    evidence.manifestHref = manifestHref;
  }

  return evidence;
}

function extractHtmlTitle(body: string): string | undefined {
  const match = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match?.[1]?.trim();
}

function extractManifestHref(body: string): string | undefined {
  const match = body.match(/<link[^>]+rel=["'][^"']*manifest[^"']*["'][^>]+href=["']([^"']+)["']/i);
  return match?.[1]?.trim();
}

function collectHeaders(headers: Headers): Record<string, string> {
  const values: Record<string, string> = {};
  headers.forEach((value, key) => {
    values[key] = value;
  });
  return values;
}

function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomUUID()}`;
}
