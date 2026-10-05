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
  'chromium-extension/src/modules/latentFeatures/analyzer.ts'
);
const outputPath = join(artifactDirectory, 'blanche-latent-feature-audit.json');
const startUrl = 'https://wellsoffice.ceo.wellsfargo.com/';
const origin = new URL(startUrl).origin;
const userAgent =
  'BLANCHE-Public-JavaScript-Review/0.2 (anonymous bounded acquisition)';
const temporaryDirectory = await mkdtemp(join(tmpdir(), 'blanche-latent-audit-'));

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

  const { analyzeLatentFeatures } = await import(
    pathToFileURL(join(temporaryDirectory, 'analyzer.mjs')).href
  );
  const pageResponse = await fetch(startUrl, {
    redirect: 'follow',
    headers: {
      accept: 'text/html,application/xhtml+xml',
      'user-agent': userAgent
    }
  });
  const pageText = await pageResponse.text();
  const pageUrl = new URL(pageResponse.url);
  const pageScriptUrls = extractScriptUrls(pageText, pageUrl).filter(
    (url) => url.origin === origin
  );
  const pageScripts = await Promise.all(pageScriptUrls.map(fetchSource));
  const mvp = pageScripts.find((source) => /\/MVP2\.bundle\./u.test(source.url));
  if (!mvp) throw new Error('MVP2 bundle was not present on the public page.');

  const runtime = parseRuntime(mvp.text, mvp.url);
  const activeChunkSources = [];
  const activeNetworkChunks = deduplicateChunks([
    ...runtime.entryChunks,
    ...runtime.transitiveSharedDependencies
  ]);
  for (const chunk of activeNetworkChunks) {
    if (!chunk.url) continue;
    activeChunkSources.push(await fetchSource(new URL(chunk.url)));
  }

  const allSources = deduplicateSources([...pageScripts, ...activeChunkSources]);
  const scriptAnalyses = allSources.map((source) => {
    const candidates = analyzeLatentFeatures({
      textSources: [
        {
          sourceKind: 'bundle',
          label: new URL(source.url).pathname.split('/').pop() || source.url,
          sourceUrl: source.url,
          text: source.text,
          contentType: source.contentType
        }
      ],
      storageEntries: [],
      structuredSources: [],
      runtimeObservedCandidates: [],
      maxCandidates: 250
    });

    return {
      url: source.url,
      status: source.status,
      byteLength: source.byteLength,
      sha256: source.sha256,
      blancheCandidates: candidates.map((candidate) => ({
        key: candidate.key,
        currentValue: candidate.currentValue,
        suggestedValue: candidate.suggestedValue,
        confidence: candidate.confidence,
        probeable: candidate.probeable,
        evidence: candidate.evidence
      })),
      exactToggleExpressions: extractToggleExpressions(source.text),
      routeDefinitions: extractRouteDefinitions(source.text),
      componentMappings: extractComponentMappings(source.text)
    };
  });

  const report = {
    kind: 'blanche.public-latent-feature-audit',
    generatedAt: new Date().toISOString(),
    collection: {
      mode: 'anonymous-public-read',
      startUrl,
      finalPage: `${pageUrl.origin}${pageUrl.pathname}`,
      credentialsSent: false,
      extractedEnvironmentHostsContacted: false,
      featureValuesChanged: false
    },
    runtime,
    scripts: scriptAnalyses
  };

  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  process.stdout.write(
    `${JSON.stringify({
      outputPath,
      pageScripts: pageScripts.length,
      activeChunkScripts: activeChunkSources.length,
      runtimeManifestPairs: runtime.manifestPairCount,
      entryChunkCount: runtime.entryChunks.length,
      candidateCount: scriptAnalyses.reduce(
        (count, script) => count + script.blancheCandidates.length,
        0
      ),
      toggleExpressionCount: scriptAnalyses.reduce(
        (count, script) => count + script.exactToggleExpressions.length,
        0
      ),
      routeDefinitionCount: scriptAnalyses.reduce(
        (count, script) => count + script.routeDefinitions.length,
        0
      ),
      componentMappingCount: scriptAnalyses.reduce(
        (count, script) => count + script.componentMappings.length,
        0
      )
    }, null, 2)}\n`
  );
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}

async function fetchSource(url) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: {
      accept: 'application/javascript,text/javascript,*/*;q=0.1',
      'user-agent': userAgent
    }
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to fetch ${url.href}: HTTP ${response.status}`);
  }
  return {
    url: response.url,
    status: response.status,
    contentType: response.headers.get('content-type') || undefined,
    byteLength: Buffer.byteLength(text, 'utf8'),
    sha256: createHash('sha256').update(text, 'utf8').digest('hex'),
    text
  };
}

function parseRuntime(source, sourceUrl) {
  const entryMatch =
    /Promise\.all\(\[(?<calls>(?:[A-Za-z_$][\w$]*\.e\(\d+\),?)+)\]\)\.then\([^)]*\.bind\([^,]+,(?<module>\d+)\)\)/u.exec(
      source
    );
  if (!entryMatch?.groups) throw new Error('Unable to identify the MVP2 entry chunks.');
  const entryChunkIds = [...entryMatch.groups.calls.matchAll(/\.e\((\d+)\)/gu)].map(
    (match) => Number(match[1])
  );

  const resolverStart = source.indexOf('.u=function');
  const resolverEnd = source.indexOf('}[e]+".js"', resolverStart);
  if (resolverStart < 0 || resolverEnd < 0) {
    throw new Error('Unable to identify the MVP2 JavaScript chunk resolver.');
  }
  const resolverText = source.slice(resolverStart, resolverEnd + 10);
  const manifest = new Map();
  for (const match of resolverText.matchAll(/(?<id>\d+(?:e\d+)?):"(?<hash>[a-f0-9]{20})"/gu)) {
    manifest.set(Number(match.groups.id), {
      hash: match.groups.hash,
      offset: resolverStart + match.index
    });
  }
  const baseUrl = new URL('./', sourceUrl);
  const specialChunk = /(?<id>\d+)===e\?e\+"\.bundle\.(?<hash>[a-f0-9]{20})\.js"/u.exec(
    resolverText
  );
  const specialId = specialChunk ? Number(specialChunk.groups.id) : undefined;
  const specialHash = specialChunk?.groups.hash;

  const entryChunks = entryChunkIds.map((id) => {
    if (id === specialId) {
      const fileName = `${id}.bundle.${specialHash}.js`;
      return {
        id,
        kind: 'network-js',
        hash: specialHash,
        manifestOffset: resolverStart + specialChunk.index,
        url: new URL(fileName, baseUrl).href
      };
    }
    const entry = manifest.get(id);
    if (!entry) {
      return {
        id,
        kind: 'runtime-or-shared-chunk',
        note: 'No JavaScript filename is emitted by the runtime resolver for this ID.'
      };
    }
    const fileName = `${id}.chunk.${entry.hash}.js`;
    return {
      id,
      kind: 'network-js',
      hash: entry.hash,
      manifestOffset: entry.offset,
      url: new URL(fileName, baseUrl).href
    };
  });

  const consumesIndex = source.indexOf('.f.consumes=function');
  const consumerMapStart = source.lastIndexOf('n={},t={', consumesIndex);
  const consumerMapEnd = source.indexOf('},r={', consumerMapStart);
  const consumerMapText =
    consumerMapStart >= 0 && consumerMapEnd > consumerMapStart
      ? source.slice(consumerMapStart, consumerMapEnd + 1)
      : '';
  const transitiveIds = [
    ...new Set(
      [...consumerMapText.matchAll(/\.e\((\d+(?:e\d+)?)\)/gu)].map((match) =>
        Number(match[1])
      )
    )
  ];
  const transitiveSharedDependencies = transitiveIds.map((id) => {
    if (id === specialId) {
      const fileName = `${id}.bundle.${specialHash}.js`;
      return {
        id,
        kind: 'network-js',
        hash: specialHash,
        manifestOffset: resolverStart + specialChunk.index,
        url: new URL(fileName, baseUrl).href
      };
    }
    const entry = manifest.get(id);
    if (!entry) {
      return {
        id,
        kind: 'runtime-or-shared-chunk',
        note: 'No JavaScript filename is emitted by the runtime resolver for this ID.'
      };
    }
    return {
      id,
      kind: 'network-js',
      hash: entry.hash,
      manifestOffset: entry.offset,
      url: new URL(`${id}.chunk.${entry.hash}.js`, baseUrl).href
    };
  });

  return {
    sourceUrl,
    entryExpressionOffset: entryMatch.index,
    entryModuleId: Number(entryMatch.groups.module),
    manifestOffset: resolverStart,
    manifestPairCount: manifest.size,
    entryChunks,
    sharedConsumerMapOffset: consumerMapStart,
    transitiveSharedDependencies
  };
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

function deduplicateSources(sources) {
  return [...new Map(sources.map((source) => [source.url, source])).values()];
}

function deduplicateChunks(chunks) {
  return [
    ...new Map(
      chunks.filter((chunk) => chunk.url).map((chunk) => [chunk.url, chunk])
    ).values()
  ];
}

function extractToggleExpressions(source) {
  const results = [];
  const patterns = [
    {
      kind: 'object-toggle',
      expression:
        /(?:["'`]([^"'`]{2,160})["'`]|([A-Za-z_$][\w$.-]{1,159}))\s*:\s*(true|false|!0|!1|0|1|["'`](?:enabled|disabled|on|off|control|treatment|yes|no)["'`])/gu
    },
    {
      kind: 'assignment-toggle',
      expression: /\.([A-Za-z_$][\w$]{1,159})\s*=\s*(true|false|!0|!1|0|1)(?![\w$])/gu
    },
    {
      kind: 'provider-call',
      expression:
        /(?:isEnabled|isFeatureEnabled|featureEnabled|hasFeature|useFeature|variation|getFeatureFlag|getBooleanValue|checkGate|isGateEnabled)\s*\(\s*["'`]([^"'`]{2,160})["'`]/gu
    },
    {
      kind: 'opaque-hash-pair',
      expression: /["'`]([a-f0-9]{8,64})["'`]\s*:\s*["'`]([a-f0-9]{8,64})["'`]/giu
    }
  ];

  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern.expression)) {
      const contextStart = Math.max(0, match.index - 100);
      const contextEnd = Math.min(source.length, match.index + match[0].length + 100);
      const context = source.slice(contextStart, contextEnd);
      const key = match[1] ?? match[2];
      const flagShaped =
        /(?:^|[-_.:/])(?:feature|features|flag|flags|experiment|experiments|variant|variation|rollout|beta|preview|labs?|gate|gates|toggle|toggles|enabled?|disabled?)(?:$|[-_.:/])/iu.test(
          key || ''
        ) ||
        /(?:feature|flag|experiment|variant|variation|rollout|preview|beta|labs?|gate|toggle|enabled|disabled|new[A-Z]|legacy[A-Z])/u.test(
          key || ''
        ) ||
        /feature|flag|experiment|variant|gate/iu.test(context);
      if (pattern.kind !== 'opaque-hash-pair' && !flagShaped && pattern.kind !== 'provider-call') {
        continue;
      }
      results.push({
        kind: pattern.kind,
        offset: match.index,
        expression: match[0],
        key,
        value: match[3],
        context: context.replace(/\s+/gu, ' ')
      });
    }
  }
  return results;
}

function extractRouteDefinitions(source) {
  const results = [];
  const expression =
    /\.Route,\{key:["'](?<key>[^"']+)["'],path:["'](?<path>[^"']*)["']/gu;
  for (const match of source.matchAll(expression)) {
    results.push({
      offset: match.index,
      key: match.groups.key,
      path: match.groups.path,
      expression: match[0]
    });
  }
  return results;
}

function extractComponentMappings(source) {
  const results = [];
  const expression =
    /["'](?<layout>auth-hub-mfe|account-unlock-mfe|#\/newuser\/(?:profile|termsofuse))["']:\[\{contentName:["'](?<contentName>[^"']+)["'],tag:["'](?<tag>[^"']+)["'],url:[^,]+,scope:["'](?<scope>[^"']+)["'],remoteKey:["'](?<remoteKey>[^"']+)["'],component:["'](?<component>[^"']+)["']/gu;
  for (const match of source.matchAll(expression)) {
    results.push({
      offset: match.index,
      layout: match.groups.layout,
      contentName: match.groups.contentName,
      tag: match.groups.tag,
      scope: match.groups.scope,
      remoteKey: match.groups.remoteKey,
      component: match.groups.component
    });
  }
  return results;
}
