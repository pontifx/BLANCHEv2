import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const artifactDirectory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(artifactDirectory, '../..');
const analyzerEntry = join(
  repoRoot,
  'chromium-extension/src/modules/latentFeatures/scriptPurposeAnalyzer.ts'
);
const outputPath = join(artifactDirectory, 'blanche-javascript-audit.json');
const startUrl = 'https://wellsoffice.ceo.wellsfargo.com/';
const allowedScriptOrigin = new URL(startUrl).origin;
const sourceLimit = 512 * 1024;
const combinedLimit = 2 * 1024 * 1024;
const scriptLimit = 8;
const userAgent =
  'BLANCHE-Public-JavaScript-Review/0.1 (anonymous bounded acquisition)';

const temporaryDirectory = await mkdtemp(join(tmpdir(), 'blanche-public-js-audit-'));

try {
  await build({
    entryPoints: { analyzer: analyzerEntry },
    outdir: temporaryDirectory,
    outExtension: { '.js': '.mjs' },
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'es2022',
    logLevel: 'silent'
  });

  const { analyzeScriptPurpose } = await import(
    pathToFileURL(join(temporaryDirectory, 'analyzer.mjs')).href
  );
  const pageResponse = await fetch(startUrl, {
    method: 'GET',
    redirect: 'follow',
    headers: {
      accept: 'text/html,application/xhtml+xml',
      'user-agent': userAgent
    }
  });
  const pageText = await pageResponse.text();
  const finalPageUrl = new URL(pageResponse.url);
  const scriptUrls = extractScriptUrls(pageText, finalPageUrl)
    .filter((url) => url.origin === allowedScriptOrigin)
    .slice(0, scriptLimit);
  const authzUrl = finalPageUrl.searchParams.get('authzUrl');
  const authzEndpoint = sanitizeAuthzEndpoint(authzUrl);
  const scripts = [];
  let retainedCharacters = 0;

  for (const scriptUrl of scriptUrls) {
    if (retainedCharacters >= combinedLimit) break;

    const response = await fetch(scriptUrl, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        accept: 'application/javascript,text/javascript,*/*;q=0.1',
        'user-agent': userAgent
      }
    });
    const body = await response.text();
    const remaining = combinedLimit - retainedCharacters;
    const retainedText = body.slice(0, Math.min(sourceLimit, remaining));
    retainedCharacters += retainedText.length;
    const sha256 = createHash('sha256').update(body, 'utf8').digest('hex');
    const finalScriptUrl = new URL(response.url);
    const assessment = analyzeScriptPurpose(
      {
        sourceKind: 'external',
        label: finalScriptUrl.pathname.split('/').pop() || finalScriptUrl.pathname,
        sourceUrl: scriptUrl.href,
        finalUrl: finalScriptUrl.href,
        text: retainedText,
        contentType: response.headers.get('content-type') || undefined,
        sha256,
        declaredByteLength: Buffer.byteLength(body, 'utf8'),
        acquiredAt: new Date().toISOString(),
        truncated: retainedText.length < body.length
      },
      {
        scope: {
          disposition: 'in-scope',
          ownership: 'first-party',
          matchedRuleIds: ['user-authorized-public-wellsfargo-surface']
        }
      }
    );

    scripts.push({
      url: finalScriptUrl.href,
      status: response.status,
      contentType: response.headers.get('content-type'),
      lastModified: response.headers.get('last-modified'),
      byteLength: Buffer.byteLength(body, 'utf8'),
      sha256,
      truncated: retainedText.length < body.length,
      blancheAnalysis: summarizeAssessment(assessment),
      explicitEnvironmentMappings: extractEnvironmentMappings(retainedText)
    });
  }

  const report = {
    kind: 'blanche.public-javascript-audit',
    generatedAt: new Date().toISOString(),
    collection: {
      mode: 'anonymous-public-read',
      startUrl,
      credentialsSent: false,
      extractedEnvironmentHostsContacted: false,
      limits: {
        scriptCount: scriptLimit,
        charactersPerScript: sourceLimit,
        combinedCharacters: combinedLimit
      }
    },
    vantageAuthSurface: {
      signOnEntry: startUrl,
      signOnPage: `${finalPageUrl.origin}${finalPageUrl.pathname}`,
      authorizationEndpoint: authzEndpoint
    },
    scripts
  };

  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

function extractScriptUrls(html, baseUrl) {
  const urls = new Map();
  const pattern = /<script\b[^>]*\bsrc\s*=\s*(["'])(.*?)\1/giu;
  for (const match of html.matchAll(pattern)) {
    try {
      const url = new URL(match[2], baseUrl);
      if (url.protocol === 'https:' || url.protocol === 'http:') {
        urls.set(url.href, url);
      }
    } catch {
      // Ignore malformed script references.
    }
  }
  return [...urls.values()];
}

function sanitizeAuthzEndpoint(rawUrl) {
  if (!rawUrl) return null;
  try {
    const url = new URL(rawUrl);
    return `${url.origin}${url.pathname}`;
  } catch {
    return null;
  }
}

function extractEnvironmentMappings(source) {
  const mappings = [];
  const objectPattern = /([A-Z][A-Z0-9_]{5,})\s*:\s*\{([^{}]{1,3000})\}/gu;
  for (const objectMatch of source.matchAll(objectPattern)) {
    const mappingKey = objectMatch[1];
    const objectBody = objectMatch[2];
    const environmentPattern = /(?:^|,)\s*(sit|dev)\s*:\s*(["'])(https?:\/\/.*?)\2/giu;
    for (const environmentMatch of objectBody.matchAll(environmentPattern)) {
      try {
        const resourceUrl = new URL(environmentMatch[3]);
        mappings.push({
          mappingKey,
          environment: environmentMatch[1].toUpperCase(),
          hostname: resourceUrl.hostname,
          resourceUrl: resourceUrl.href
        });
      } catch {
        // Ignore malformed URL literals.
      }
    }
  }
  return mappings;
}

function summarizeAssessment(assessment) {
  return {
    artifactId: assessment.artifact.artifactId,
    transform: {
      primary: assessment.transform.primary,
      detected: assessment.transform.detected,
      confidence: assessment.transform.confidence,
      complexityScore: assessment.transform.complexityScore,
      metrics: assessment.transform.metrics
    },
    coverage: {
      sourceIntegrity: assessment.coverage.sourceIntegrity,
      gaps: assessment.coverage.gaps.map((gap) => gap.code)
    },
    purposeClaims: assessment.purposeClaims.map((claim) => ({
      category: claim.category,
      confidence: claim.confidence,
      score: claim.score
    })),
    reviewPriority: assessment.reviewPriority,
    environmentIndicators: assessment.indicators
      .filter(
        (indicator) =>
          indicator.kind === 'host' && /(?:dev|sit)/iu.test(indicator.value)
      )
      .map((indicator) => ({ kind: indicator.kind, value: indicator.value }))
  };
}
