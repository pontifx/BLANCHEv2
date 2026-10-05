import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const artifactDirectory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(artifactDirectory, '../..');
const outputPath = join(artifactDirectory, 'blanche-feature-map-audit.json');
const temporaryDirectory = await mkdtemp(join(tmpdir(), 'blanche-feature-map-audit-'));
const signOnEntry = 'https://wellsoffice.ceo.wellsfargo.com/';
const allowedOrigin = new URL(signOnEntry).origin;
const perSourceLimit = 4 * 1024 * 1024;
const combinedLimit = 16 * 1024 * 1024;
const sourceLimit = 24;
const spacingMs = 750;
const userAgent = 'BLANCHE-Public-Feature-Map-Review/0.1 (anonymous bounded acquisition)';
let lastRequestStartedAt = 0;

try {
  await build({
    entryPoints: {
      purposeAnalyzer: join(
        repoRoot,
        'chromium-extension/src/modules/latentFeatures/scriptPurposeAnalyzer.ts'
      ),
      latentAnalyzer: join(
        repoRoot,
        'chromium-extension/src/modules/latentFeatures/analyzer.ts'
      )
    },
    outdir: temporaryDirectory,
    outExtension: { '.js': '.mjs' },
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'es2022',
    logLevel: 'silent'
  });

  const { analyzeScriptPurpose } = await import(
    pathToFileURL(join(temporaryDirectory, 'purposeAnalyzer.mjs')).href
  );
  const { analyzeLatentFeatures } = await import(
    pathToFileURL(join(temporaryDirectory, 'latentAnalyzer.mjs')).href
  );

  const page = await fetchBounded(signOnEntry, 256 * 1024, 'text/html,application/xhtml+xml');
  const pageUrl = new URL(page.finalUrl);
  const pageScriptUrls = extractScriptUrls(page.text, pageUrl).filter(
    (url) => url.origin === allowedOrigin
  );
  const mainBundleUrl = pageScriptUrls.find((url) => /\/MVP2\.bundle\.[a-f0-9]+\.js$/iu.test(url.pathname));
  const globalsBundleUrl = pageScriptUrls.find((url) => /\/globals\.bundle\.[a-f0-9]+\.js$/iu.test(url.pathname));
  if (!mainBundleUrl || !globalsBundleUrl) {
    throw new Error('The current sign-on page did not expose both expected production bundles.');
  }

  const sources = [];
  let combinedBytes = 0;
  for (const url of [mainBundleUrl, globalsBundleUrl]) {
    const source = await acquireSource(url, combinedLimit - combinedBytes);
    combinedBytes += source.retainedByteLength;
    sources.push(source);
  }

  const mainSource = sources.find((source) => source.url === mainBundleUrl.href);
  const globalsSource = sources.find((source) => source.url === globalsBundleUrl.href);
  const manifest = parseWebpackManifest(mainSource.text, mainBundleUrl);
  const globalsManifest = parseWebpackManifest(globalsSource.text, globalsBundleUrl);
  const startupUrls = manifest.startupChunks
    .filter((chunk) => chunk.url)
    .map((chunk) => new URL(chunk.url));

  for (const url of startupUrls) {
    if (sources.length >= sourceLimit || combinedBytes >= combinedLimit) break;
    if (sources.some((source) => source.url === url.href)) continue;
    const source = await acquireSource(url, combinedLimit - combinedBytes);
    combinedBytes += source.retainedByteLength;
    sources.push(source);
  }

  const assessments = sources.map((source) => {
    const assessment = analyzeScriptPurpose(
      {
        sourceKind: 'external',
        label: new URL(source.url).pathname.split('/').pop() || new URL(source.url).pathname,
        sourceUrl: source.url,
        finalUrl: source.url,
        text: source.text,
        contentType: source.contentType || undefined,
        sha256: source.sha256,
        declaredByteLength: source.declaredByteLength,
        acquiredAt: source.acquiredAt,
        truncated: source.truncated
      },
      {
        scope: {
          disposition: 'in-scope',
          ownership: 'first-party',
          matchedRuleIds: ['user-authorized-public-wellsfargo-surface']
        },
        options: {
          maxEvidence: 500,
          maxIndicators: 250,
          maxClaims: 32,
          maxSnippetCharacters: 240
        }
      }
    );
    return summarizeAssessment(source, assessment);
  });

  const latentCandidates = analyzeLatentFeatures({
    textSources: sources.map((source) => ({
      sourceKind: 'bundle',
      label: new URL(source.url).pathname.split('/').pop() || new URL(source.url).pathname,
      sourceUrl: source.url,
      contentType: source.contentType || undefined,
      truncated: source.truncated,
      text: source.text
    })),
    storageEntries: [],
    structuredSources: [],
    runtimeObservedCandidates: [],
    maxCandidates: 500
  }).map(summarizeCandidate);

  const explicitOffCandidates = latentCandidates.filter((candidate) =>
    equalJson(candidate.currentValue, candidate.disabledValue)
  );
  const referenceOnlyCandidates = latentCandidates.filter(
    (candidate) => candidate.currentValue === undefined
  );
  const remoteMaps = extractRemoteMaps(sources);
  const remoteFeatureBindings = extractRemoteFeatureBindings(sources);
  const reactRoutes = extractReactRoutes(sources);
  const relevantRouteLiterals = extractRelevantRouteLiterals(sources);
  const sourceCorrelations = sources.map((source) => ({
    sourceUrl: source.url,
    explicitOffCandidates: explicitOffCandidates
      .filter((candidate) => candidate.sourceUrls.includes(source.url))
      .map((candidate) => candidate.key),
    referenceOnlyCandidates: referenceOnlyCandidates
      .filter((candidate) => candidate.sourceUrls.includes(source.url))
      .map((candidate) => candidate.key),
    sanitizedEndpoints:
      assessments
        .find((assessment) => assessment.url === source.url)
        ?.indicators.filter((indicator) => indicator.kind === 'endpoint')
        .map((indicator) => indicator.value) ?? [],
    relevantRouteLiterals: relevantRouteLiterals
      .filter((entry) => entry.sourceUrl === source.url)
      .map((entry) => entry.value)
  }));

  const report = {
    kind: 'blanche.public-feature-map-audit',
    generatedAt: new Date().toISOString(),
    collection: {
      mode: 'anonymous-public-read',
      credentialsSent: false,
      formsSubmitted: false,
      storageModified: false,
      extractedEnvironmentHostsContacted: false,
      allowedOrigin,
      limits: {
        sources: sourceLimit,
        bytesPerSource: perSourceLimit,
        combinedBytes: combinedLimit,
        requestStartSpacingMs: spacingMs
      },
      retainedSourceCount: sources.length,
      retainedBytes: combinedBytes
    },
    authSurface: {
      signOnEntry,
      signOnPage: `${pageUrl.origin}${pageUrl.pathname}`,
      authorizationEndpoint: sanitizeAuthzEndpoint(pageUrl.searchParams.get('authzUrl'))
    },
    webpack: {
      mainBundleUrl: mainBundleUrl.href,
      publicPath: manifest.publicPath,
      javascriptChunkCount: manifest.javascriptChunks.length,
      cssChunkCount: manifest.cssChunks.length,
      startupChunkCount: manifest.startupChunks.length,
      mappedStartupChunkCount: manifest.startupChunks.filter((chunk) => chunk.url).length,
      deferredMappedChunkCount: manifest.deferredChunks.length,
      startupChunks: manifest.startupChunks,
      cssChunks: manifest.cssChunks,
      deferredChunks: manifest.deferredChunks,
      globalsManifestMatchesMain:
        manifest.manifestFingerprint === globalsManifest.manifestFingerprint,
      caveat:
        'A mapped but non-startup chunk is deferred, lazy, or unused in this startup path; the hash map alone does not prove that its feature is disabled.'
    },
    moduleFederation: remoteMaps,
    remoteFeatureBindings,
    reactRoutes,
    blancheLatentFeatureAnalysis: {
      candidateCount: latentCandidates.length,
      explicitOffCandidateCount: explicitOffCandidates.length,
      referenceOnlyCandidateCount: referenceOnlyCandidates.length,
      explicitOffCandidates,
      referenceOnlyCandidates,
      allCandidates: latentCandidates,
      caveat:
        'Bundle-only candidates are static observations. An explicit false/off literal can be a default, fallback, or library option rather than a reachable application feature gate.'
    },
    relevantRouteLiterals,
    sourceCorrelations,
    sourceAssessments: assessments
  };

  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  process.stdout.write(
    `${JSON.stringify({
      kind: report.kind,
      outputPath,
      collection: report.collection,
      authSurface: report.authSurface,
      webpack: {
        mainBundleUrl: report.webpack.mainBundleUrl,
        publicPath: report.webpack.publicPath,
        javascriptChunkCount: report.webpack.javascriptChunkCount,
        cssChunkCount: report.webpack.cssChunkCount,
        startupChunkCount: report.webpack.startupChunkCount,
        mappedStartupChunkCount: report.webpack.mappedStartupChunkCount,
        deferredMappedChunkCount: report.webpack.deferredMappedChunkCount,
        globalsManifestMatchesMain: report.webpack.globalsManifestMatchesMain
      },
      moduleFederationMapCount: report.moduleFederation.length,
      remoteFeatureBindingCount: report.remoteFeatureBindings.length,
      reactRouteCount: report.reactRoutes.length,
      latentFeatureSummary: {
        candidateCount: latentCandidates.length,
        explicitOffCandidateCount: explicitOffCandidates.length,
        referenceOnlyCandidateCount: referenceOnlyCandidates.length
      },
      relevantRouteLiteralCount: relevantRouteLiterals.length
    }, null, 2)}\n`
  );
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

async function acquireSource(url, remainingBytes) {
  if (url.origin !== allowedOrigin || !url.pathname.startsWith('/ceosignon/')) {
    throw new Error(`Refusing out-of-bound script URL: ${url.href}`);
  }
  const maxBytes = Math.max(0, Math.min(perSourceLimit, remainingBytes));
  if (maxBytes === 0) throw new Error('The combined source cap was reached.');
  const response = await fetchBounded(
    url.href,
    maxBytes,
    'application/javascript,text/javascript,*/*;q=0.1'
  );
  return {
    url: response.finalUrl,
    status: response.status,
    contentType: response.contentType,
    lastModified: response.lastModified,
    acquiredAt: new Date().toISOString(),
    declaredByteLength: response.declaredByteLength,
    retainedByteLength: response.retainedByteLength,
    truncated: response.truncated,
    sha256: createHash('sha256').update(response.bytes).digest('hex'),
    text: response.text
  };
}

async function fetchBounded(rawUrl, maxBytes, accept) {
  let url = new URL(rawUrl);
  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    if (url.origin !== allowedOrigin) {
      throw new Error(`Refusing redirect outside the production sign-on origin: ${url.href}`);
    }
    const waitMs = Math.max(0, spacingMs - (Date.now() - lastRequestStartedAt));
    if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
    lastRequestStartedAt = Date.now();
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      headers: { accept, 'user-agent': userAgent }
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) throw new Error(`Redirect without Location from ${url.href}`);
      url = new URL(location, url);
      continue;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status} from ${url.href}`);
    const bounded = await readBoundedBody(response, maxBytes);
    return {
      finalUrl: url.href,
      status: response.status,
      contentType: response.headers.get('content-type'),
      lastModified: response.headers.get('last-modified'),
      declaredByteLength: Number(response.headers.get('content-length')) || bounded.bytes.length,
      retainedByteLength: bounded.bytes.length,
      truncated: bounded.truncated,
      bytes: bounded.bytes,
      text: new TextDecoder().decode(bounded.bytes)
    };
  }
  throw new Error(`Too many redirects for ${rawUrl}`);
}

async function readBoundedBody(response, maxBytes) {
  if (!response.body) return { bytes: Buffer.alloc(0), truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let retained = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = maxBytes - retained;
    if (remaining <= 0) {
      truncated = true;
      await reader.cancel();
      break;
    }
    const chunk = Buffer.from(value);
    if (chunk.length > remaining) {
      chunks.push(chunk.subarray(0, remaining));
      retained += remaining;
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(chunk);
    retained += chunk.length;
  }
  return { bytes: Buffer.concat(chunks, retained), truncated };
}

function extractScriptUrls(html, baseUrl) {
  const urls = new Map();
  const pattern = /<script\b[^>]*\bsrc\s*=\s*(["'])(.*?)\1/giu;
  for (const match of html.matchAll(pattern)) {
    try {
      const url = new URL(match[2], baseUrl);
      if (url.protocol === 'https:' || url.protocol === 'http:') urls.set(url.href, url);
    } catch {
      // Ignore malformed script references.
    }
  }
  return [...urls.values()];
}

function parseWebpackManifest(source, bundleUrl) {
  const urlMatch = source.match(
    /[A-Za-z_$][\w$]*\.u=function\(e\)\{return (\d+)===e\?e\+"\.bundle\.([a-f0-9]+)\.js":e\+"\.chunk\."\+\{([^}]*)\}\[e\]\+"\.js"\}/u
  );
  if (!urlMatch) throw new Error(`Webpack JavaScript chunk map not found in ${bundleUrl.href}`);
  const specialId = Number(urlMatch[1]);
  const specialHash = urlMatch[2];
  const hashPairs = [...urlMatch[3].matchAll(/(\d+):"([a-f0-9]+)"/gu)].map((match) => ({
    id: Number(match[1]),
    hash: match[2]
  }));
  const publicPathMatch = source.match(/[A-Za-z_$][\w$]*\.p="([^"]+)"/u);
  const publicPath = publicPathMatch?.[1] ?? '/ceosignon/';
  const baseUrl = new URL(publicPath, bundleUrl.origin);
  const javascriptChunks = [
    {
      id: specialId,
      hash: specialHash,
      filename: `${specialId}.bundle.${specialHash}.js`,
      url: new URL(`${specialId}.bundle.${specialHash}.js`, baseUrl).href
    },
    ...hashPairs.map(({ id, hash }) => ({
      id,
      hash,
      filename: `${id}.chunk.${hash}.js`,
      url: new URL(`${id}.chunk.${hash}.js`, baseUrl).href
    }))
  ].sort((left, right) => left.id - right.id);
  const startupMatch = source.match(/Promise\.all\(\[([^\]]+)\]\)\.then/isu);
  const startupIds = startupMatch
    ? [...startupMatch[1].matchAll(/[A-Za-z_$][\w$]*\.e\((\d+)\)/gu)].map((match) => Number(match[1]))
    : [];
  const chunkById = new Map(javascriptChunks.map((entry) => [entry.id, entry]));
  const startupChunks = startupIds.map((id) => {
    const mapped = chunkById.get(id);
    return mapped ?? { id, hash: null, filename: null, url: null };
  });
  const startupIdSet = new Set(startupIds);
  const deferredChunks = javascriptChunks.filter((chunk) => !startupIdSet.has(chunk.id));
  const cssMatch = source.match(
    /[A-Za-z_$][\w$]*\.miniCssF=function\(e\)\{return e\+"\.bundle\."\+\{([^}]*)\}\[e\]\+"\.css"\}/u
  );
  const cssChunks = cssMatch
    ? [...cssMatch[1].matchAll(/(\d+):"([a-f0-9]+)"/gu)].map((match) => {
        const id = Number(match[1]);
        const hash = match[2];
        const filename = `${id}.bundle.${hash}.css`;
        return { id, hash, filename, url: new URL(filename, baseUrl).href };
      })
    : [];
  const manifestFingerprint = createHash('sha256')
    .update(JSON.stringify({ publicPath, javascriptChunks, cssChunks }))
    .digest('hex');
  return {
    publicPath,
    javascriptChunks,
    cssChunks,
    startupChunks,
    deferredChunks,
    manifestFingerprint
  };
}

function extractRemoteMaps(sources) {
  const groups = new Map();
  const objectPattern = /([A-Za-z_$][A-Za-z0-9_$]{1,100})\s*:\s*\{([^{}]{1,3000})\}/gu;
  const environmentPattern = /(?:^|,)\s*(prd|fix|uat|sit|dev|hos|local)\s*:\s*(["'])(https?:\/\/.*?)\2/giu;
  const activationPattern = /\(window\.location\.hostname,"([A-Z][A-Z0-9_]{5,})",[A-Za-z_$][\w$]*\)/gu;
  for (const source of sources) {
    const activatedKeys = new Set(
      [...source.text.matchAll(activationPattern)].map((match) => match[1])
    );
    for (const objectMatch of source.text.matchAll(objectPattern)) {
      const mappingKey = objectMatch[1];
      const environments = {};
      for (const environmentMatch of objectMatch[2].matchAll(environmentPattern)) {
        const environment = environmentMatch[1].toLowerCase();
        try {
          const resourceUrl = new URL(environmentMatch[3]);
          environments[environment] = {
            hostname: resourceUrl.hostname,
            resourceUrl: resourceUrl.href
          };
        } catch {
          // Ignore malformed URL literals.
        }
      }
      if (
        !environments.prd ||
        !environments.prd.resourceUrl.includes('remoteEntry.js') ||
        Object.keys(environments).length < 2
      ) continue;
      const existing = groups.get(mappingKey) ?? {
        mappingKey,
        environments,
        sourceUrls: [],
        activatedBySources: []
      };
      if (!existing.sourceUrls.includes(source.url)) existing.sourceUrls.push(source.url);
      if (activatedKeys.has(mappingKey) && !existing.activatedBySources.includes(source.url)) {
        existing.activatedBySources.push(source.url);
      }
      groups.set(mappingKey, existing);
    }
  }
  return [...groups.values()].sort((left, right) => left.mappingKey.localeCompare(right.mappingKey));
}

function extractRemoteFeatureBindings(sources) {
  const results = new Map();
  const pattern =
    /(?:name|contentName):"([^"]+)",tag:"Remote",url:(?:[A-Za-z_$][\w$]*\.)+([A-Za-z_$][\w$]*)\[[^\]]+\],scope:"([^"]+)",remoteKey:"([^"]+)",component:"([^"]+)"/gu;
  for (const source of sources) {
    for (const match of source.text.matchAll(pattern)) {
      const entry = {
        label: match[1],
        configurationKey: match[2],
        scope: match[3],
        remoteKey: match[4],
        component: match[5],
        sourceUrl: source.url,
        offset: match.index ?? null
      };
      results.set(
        `${entry.scope}:${entry.remoteKey}:${entry.component}:${entry.sourceUrl}`,
        entry
      );
    }
  }
  return [...results.values()].sort(
    (left, right) => left.component.localeCompare(right.component) || left.sourceUrl.localeCompare(right.sourceUrl)
  );
}

function extractReactRoutes(sources) {
  const results = new Map();
  const pattern = /\.Route,\{key:"([^"]+)",path:"([^"]*)",element:/gu;
  for (const source of sources) {
    for (const match of source.text.matchAll(pattern)) {
      const entry = {
        key: match[1],
        path: match[2],
        sourceUrl: source.url,
        offset: match.index ?? null
      };
      results.set(`${entry.sourceUrl}:${entry.key}:${entry.path}`, entry);
    }
  }
  return [...results.values()].sort(
    (left, right) => left.sourceUrl.localeCompare(right.sourceUrl) || left.key.localeCompare(right.key)
  );
}

function extractRelevantRouteLiterals(sources) {
  const tokenPattern = /(?:auth|login|sign[-_]?on|password|self[-_]?help|forgot|recover|reset|register|contact|terms|privacy|system|access|token|user|company|sso|otp|mfa|challenge|verify)/iu;
  const literalPattern = /(["'`])(\/[A-Za-z0-9_./?&=:{\}-]{1,220})\1/gu;
  const results = new Map();
  for (const source of sources) {
    for (const match of source.text.matchAll(literalPattern)) {
      const value = match[2];
      if (!tokenPattern.test(value) || /\.(?:js|css|png|svg|ico|woff2?)(?:\?|$)/iu.test(value)) continue;
      const sanitized = sanitizeRelativeRoute(value);
      if (!sanitized) continue;
      const key = `${source.url}:${sanitized}`;
      if (!results.has(key)) {
        results.set(key, { sourceUrl: source.url, value: sanitized, offset: match.index ?? null });
      }
    }
  }
  return [...results.values()].sort(
    (left, right) => left.sourceUrl.localeCompare(right.sourceUrl) || left.value.localeCompare(right.value)
  );
}

function sanitizeRelativeRoute(value) {
  try {
    const url = new URL(value, allowedOrigin);
    const parameterNames = [...new Set(url.searchParams.keys())].sort();
    return `${url.pathname}${parameterNames.length ? `?${parameterNames.join('&')}` : ''}`;
  } catch {
    return null;
  }
}

function summarizeAssessment(source, assessment) {
  return {
    url: source.url,
    status: source.status,
    contentType: source.contentType,
    lastModified: source.lastModified,
    declaredByteLength: source.declaredByteLength,
    retainedByteLength: source.retainedByteLength,
    truncated: source.truncated,
    sha256: source.sha256,
    transform: {
      primary: assessment.transform.primary,
      detected: assessment.transform.detected,
      confidence: assessment.transform.confidence
    },
    purposeClaims: assessment.purposeClaims.map((claim) => ({
      category: claim.category,
      confidence: claim.confidence,
      score: claim.score
    })),
    indicators: assessment.indicators
      .filter((indicator) =>
        ['endpoint', 'host', 'feature-key', 'storage-key'].includes(indicator.kind)
      )
      .map((indicator) => ({
        kind: indicator.kind,
        value: indicator.value,
        confidence: indicator.confidence
      }))
  };
}

function summarizeCandidate(candidate) {
  return {
    id: candidate.id,
    key: candidate.key,
    normalizedKey: candidate.normalizedKey,
    currentValue: candidate.currentValue,
    suggestedValue: candidate.suggestedValue,
    enabledValue: candidate.enabledValue,
    disabledValue: candidate.disabledValue,
    confidence: candidate.confidence,
    controlSurface: candidate.controlSurface,
    probeable: candidate.probeable,
    sourceUrls: [
      ...new Set(candidate.evidence.map((entry) => entry.sourceUrl).filter(Boolean))
    ],
    evidence: candidate.evidence.map((entry) => ({
      sourceKind: entry.sourceKind,
      label: entry.label,
      sourceUrl: entry.sourceUrl,
      detail: entry.detail,
      snippet: entry.snippet
    }))
  };
}

function equalJson(left, right) {
  return left !== undefined && right !== undefined && JSON.stringify(left) === JSON.stringify(right);
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
