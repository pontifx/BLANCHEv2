import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = await mkdtemp(join(tmpdir(), 'blanche-javascript-analysis-'));

try {
  await build({
    entryPoints: {
      analyzer: join(
        repoRoot,
        'chromium-extension/src/modules/latentFeatures/scriptPurposeAnalyzer.ts'
      ),
      latentAnalyzer: join(
        repoRoot,
        'chromium-extension/src/modules/latentFeatures/analyzer.ts'
      ),
      rubric: join(
        repoRoot,
        'chromium-extension/src/modules/latentFeatures/scriptPurposeRubric.ts'
      ),
      workbench: join(
        repoRoot,
        'chromium-extension/src/shared/latentFeatureWorkbench.ts'
      ),
      pageSignals: join(
        repoRoot,
        'chromium-extension/src/modules/latentFeatures/pageSignalsScript.ts'
      )
    },
    outdir: outputDirectory,
    outExtension: { '.js': '.mjs' },
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'es2022',
    logLevel: 'silent'
  });

  const analyzer = await import(
    pathToFileURL(join(outputDirectory, 'analyzer.mjs')).href
  );
  const latentAnalyzer = await import(
    pathToFileURL(join(outputDirectory, 'latentAnalyzer.mjs')).href
  );
  const rubric = await import(pathToFileURL(join(outputDirectory, 'rubric.mjs')).href);
  const workbench = await import(
    pathToFileURL(join(outputDirectory, 'workbench.mjs')).href
  );
  const pageSignals = await import(
    pathToFileURL(join(outputDirectory, 'pageSignals.mjs')).href
  );

  testTransformClassification(analyzer);
  testRawDocumentSourceMapAndTruncation(analyzer);
  testPurposeClassifications(analyzer);
  testBehaviorMaturity(analyzer);
  testSanitizedIndicators(analyzer);
  testReviewPriorityContract(analyzer, rubric);
  testDeterministicResults(analyzer);
  testStageScopeGates(analyzer);
  testAnalysisCaps(analyzer, rubric);
  testLatentFeatureToggleModel(latentAnalyzer);
  testWorkbenchPersistenceHardening(analyzer, rubric, workbench);
  testPageSignalLabelPrivacy(pageSignals);

  console.log('JavaScript analysis tests passed.');
} finally {
  await rm(outputDirectory, { recursive: true, force: true });
}

function testTransformClassification({ analyzeScriptPurpose }) {
  const readable = analyzeScriptPurpose(
    makeSource(`
      function renderGreeting(name) {
        const heading = document.createElement('h1');
        heading.textContent = 'Hello ' + name;
        document.body.appendChild(heading);
      }

      renderGreeting('reviewer');
    `)
  );
  assert.equal(readable.transform.primary, 'readable');
  assert.ok(readable.transform.detected.includes('readable'));
  assert.equal(readable.transform.complexityScore, 0);

  const minifiedText = `(()=>{${'let a=1;a+=2;'.repeat(120)}return a})()`;
  const minified = analyzeScriptPurpose(makeSource(minifiedText, { label: 'app.min.js' }));
  assert.equal(minified.transform.primary, 'minified');
  assert.ok(minified.transform.metrics.longestLineLength >= 1_000);

  const bundled = analyzeScriptPurpose(
    makeSource(
      `
        const modules = {};
        function __webpack_require__(moduleId) {
          return modules[moduleId]();
        }
        self.webpackChunkPortal = self.webpackChunkPortal || [];
      `,
      { label: 'runtime.bundle.js' }
    )
  );
  assert.equal(bundled.transform.primary, 'bundled');
  assert.ok(bundled.transform.detected.includes('bundled'));
  assert.ok(bundled.transform.signals.some((signal) => signal.code === 'TRANSFORM_WEBPACK_BUNDLE'));

  const deanEdwardsPacked = analyzeScriptPurpose(
    makeSource(
      "eval(function(p,a,c,k,e,d){e=function(c){return c.toString(a)};return p}('0(\"1\")',2,2,'alert|ok'.split('|'),0,{}));",
      { label: 'packed.js' }
    )
  );
  assert.equal(deanEdwardsPacked.transform.primary, 'packed');
  assert.ok(
    deanEdwardsPacked.transform.signals.some((signal) => signal.code === 'TRANSFORM_PACKER_EVAL')
  );
  assert.ok(
    deanEdwardsPacked.coverage.gaps.some((gap) => gap.code === 'UNRESOLVED_PACKED_PAYLOAD')
  );

  const obfuscated = analyzeScriptPurpose(
    makeSource(
      `
        var _0xa11ce = 1, _0xb22cf = 2, _0xc33de = 3;
        while (true) { switch (_0xa11ce) { case 1: _0xa11ce = 2; break; default: break; } }
      `,
      { label: 'uglified.js' }
    )
  );
  assert.equal(obfuscated.transform.primary, 'obfuscated');
  assert.ok(obfuscated.transform.detected.includes('obfuscated'));
  assert.ok(
    obfuscated.transform.signals.some((signal) => signal.code === 'TRANSFORM_HEX_IDENTIFIERS')
  );
  assert.ok(
    obfuscated.transform.signals.some(
      (signal) => signal.code === 'TRANSFORM_CONTROL_FLOW_FLATTENING'
    )
  );
}

function testRawDocumentSourceMapAndTruncation({ analyzeScriptPurpose }) {
  const sourceMapUrl =
    'https://map-user:map-password@cdn.example.test/maps/app.js.map?token=private#fragment';
  const rawDocument = makeSource(
    `
      createRoot(document.getElementById('root')).render(app);
      //# sourceMappingURL=${sourceMapUrl}
    `,
    {
      sourceKind: 'document',
      label: 'raw JavaScript document',
      sourceUrl: 'https://app.example.test/assets/app.js',
      finalUrl: 'https://app.example.test/assets/app.js',
      declaredByteLength: 50_000,
      truncated: true,
      sha256: 'not-a-content-hash'
    }
  );

  const unavailable = analyzeScriptPurpose(rawDocument);
  assert.equal(unavailable.artifact.sourceKind, 'document');
  assert.equal(unavailable.artifact.sha256, undefined);
  assert.equal(unavailable.coverage.status, 'partial');
  assert.ok(unavailable.coverage.byteCoverageRatio < 1);
  assertCoverageGap(unavailable, 'TRUNCATED_SOURCE');
  assertCoverageGap(unavailable, 'MISSING_CONTENT_HASH');
  assertCoverageGap(unavailable, 'SOURCE_MAP_UNAVAILABLE');

  const sourceMapIndicator = findIndicator(unavailable, 'source-map');
  assert.equal(sourceMapIndicator.value, 'https://cdn.example.test/maps/app.js.map');
  assert.doesNotMatch(sourceMapIndicator.value, /map-user|map-password|private|fragment/);

  const matched = analyzeScriptPurpose(
    {
      ...rawDocument,
      declaredByteLength: undefined,
      truncated: false,
      sha256: 'a'.repeat(64)
    },
    {
      sourceMap: {
        status: 'matched',
        url: 'https://cdn.example.test/maps/app.js.map',
        sha256: 'b'.repeat(64),
        symbols: ['renderDashboard', 'AdminConsole']
      }
    }
  );
  assert.ok(!matched.coverage.gaps.some((gap) => gap.code === 'SOURCE_MAP_UNAVAILABLE'));
  assert.equal(findIndicator(matched, 'source-map').confidence, 'high');
  assert.ok(
    matched.evidence.some(
      (entry) => entry.evidenceClass === 'source-map' && entry.label === 'Matched source-map semantics'
    )
  );

  const mismatch = analyzeScriptPurpose(rawDocument, {
    sourceMap: { status: 'mismatch', url: 'https://cdn.example.test/maps/app.js.map' }
  });
  assertCoverageGap(mismatch, 'SOURCE_MAP_MISMATCH');
}

function testPurposeClassifications({ analyzeScriptPurpose }) {
  const cases = [
    {
      category: 'app-shell-ui',
      text: "createRoot(document.getElementById('root')).render(app); history.pushState({}, '', '/home');"
    },
    {
      category: 'api-data',
      text: "fetch('/api/users'); const request = gql`query Account { account { id } }`;"
    },
    {
      category: 'identity-access',
      text: "const access_token = sessionStorage.getItem('token'); loginWithRedirect();"
    },
    {
      category: 'feature-configuration',
      text: "const feature_flags = {}; if (isFeatureEnabled('preview-panel')) showPreview();"
    },
    {
      category: 'telemetry-analytics',
      text: "navigator.sendBeacon('/events', payload); analytics.track('page-view');"
    },
    {
      category: 'storage-offline',
      text: "localStorage.setItem('draft', value); navigator.serviceWorker.register('/worker.js');"
    },
    {
      category: 'realtime-messaging',
      text: "const socket = new WebSocket('wss://stream.example.test/feed'); socket.subscribe('prices');"
    },
    {
      category: 'developer-debug-admin',
      text: 'window.__REDUX_DEVTOOLS_EXTENSION__?.connect(); const adminPanel = true;'
    }
  ];

  for (const { category, text } of cases) {
    const result = analyzeScriptPurpose(makeSource(text, { label: `${category}.js` }));
    const purpose = findPurpose(result, category);
    assert.ok(purpose.score > 0, `${category} should have scored evidence`);
    assert.ok(purpose.evidenceRefs.length > 0, `${category} should cite evidence`);
  }
}

function testBehaviorMaturity({ analyzeScriptPurpose }) {
  const maturity0 = analyzeScriptPurpose(makeSource('const answer = 42;'));
  assert.equal(findBehavior(maturity0, 'network').maturity, 0);

  const maturity1 = analyzeScriptPurpose(
    makeSource("const endpoint = 'https://api.example.test/v1/items';")
  );
  assert.equal(findBehavior(maturity1, 'network').maturity, 1);

  const maturity2 = analyzeScriptPurpose(makeSource("fetch('/api/items');"));
  assert.equal(findBehavior(maturity2, 'network').maturity, 2);

  const runtimeObservation = {
    axis: 'network',
    detail: 'GET request attributable to this script during the instrumented reload.',
    targetUrl: 'https://api.example.test/v1/items?token=secret#private',
    method: 'GET',
    evidenceId: 'runtime-network-001',
    purposeHints: ['api-data']
  };
  const maturity3 = analyzeScriptPurpose(makeSource('const answer = 42;'), {
    runtimeObservations: [runtimeObservation]
  });
  const network = findBehavior(maturity3, 'network');
  assert.equal(network.maturity, 3);
  assert.ok(
    network.evidenceRefs.some((reference) =>
      maturity3.evidence.some(
        (entry) => entry.evidenceId === reference && entry.evidenceClass === 'runtime'
      )
    )
  );
  assert.equal(maturity3.coverage.runtimeObservationCount, 1);
  assert.equal(findBehavior(maturity3, 'cross-origin-transfer').maturity, 3);
}

function testSanitizedIndicators({ analyzeScriptPurpose }) {
  const result = analyzeScriptPurpose(
    makeSource(
      `
        const endpoint = 'https://alice:swordfish@api.example.test/users/123456789?token=secret&mode=full#private-fragment';
        fetch(endpoint);
        //# sourceMappingURL=https://map-user:map-password@cdn.example.test/app.map?key=secret#private-map
      `,
      {
        sourceUrl: 'https://app.example.test/assets/app.js',
        finalUrl: 'https://app.example.test/assets/app.js'
      }
    )
  );

  const values = result.indicators.map((indicator) => indicator.value);
  assert.ok(values.includes('https://api.example.test/users/{id}?mode&token'));
  assert.ok(values.includes('api.example.test'));
  assert.ok(values.includes('https://cdn.example.test/app.map'));
  for (const value of values) {
    assert.doesNotMatch(
      value,
      /alice|swordfish|map-user|map-password|secret|full|private-fragment|private-map/i
    );
    assert.ok(!value.includes('#'), `indicator must not retain a fragment: ${value}`);
    assert.ok(!/[?&][^?&]+=/.test(value), `indicator must retain query names only: ${value}`);
  }
}

function testReviewPriorityContract({ analyzeScriptPurpose }, rubric) {
  const highInterest = analyzeScriptPurpose(
    makeSource(`
      const password = form.password;
      const adminPanel = true;
      const feature_flags = { debugMode: true };
      loginWithRedirect();
      fetch('https://api.example.test/admin/change', { method: 'POST' });
      const dynamicHandler = new Function('input', input);
      const socket = new WebSocket('wss://stream.example.test/admin');
    `),
    {
      runtimeObservations: [
        {
          axis: 'server-state-change',
          detail: 'POST was observed during the attributed scenario.',
          targetUrl: 'https://api.example.test/admin/change',
          method: 'POST',
          evidenceId: 'state-change-runtime'
        },
        {
          axis: 'identity-session-authorization',
          detail: 'Identity handling was observed.',
          evidenceId: 'identity-runtime'
        },
        {
          axis: 'latent-debug-admin',
          detail: 'The debug/admin feature path was observed.',
          evidenceId: 'admin-runtime',
          purposeHints: ['developer-debug-admin']
        }
      ]
    }
  );

  assert.equal(highInterest.reviewPriority.isVulnerabilitySeverity, false);
  assert.equal(highInterest.reviewPriority.scoreModel, rubric.SCRIPT_PURPOSE_SCORE_MODEL);
  assert.ok(highInterest.reviewPriority.score >= 0 && highInterest.reviewPriority.score <= 100);
  assert.ok(['low', 'medium', 'high', 'urgent'].includes(highInterest.reviewPriority.band));
  assert.ok(
    highInterest.reviewPriority.factors.some(
      (factor) => factor.code === 'STATE_CHANGE' && factor.appliedWeight === 25
    )
  );
  assert.ok(
    highInterest.reviewPriority.factors.some(
      (factor) => factor.code === 'IDENTITY_ACCESS' && factor.appliedWeight === 20
    )
  );

  const packedOnly = analyzeScriptPurpose(
    makeSource(
      "eval(function(p,a,c,k,e,d){return p}('answer',1,1,'answer'.split('|'),0,{}));"
    )
  );
  assert.equal(packedOnly.transform.primary, 'packed');
  assert.equal(packedOnly.reviewPriority.isVulnerabilitySeverity, false);
  assert.ok(
    !packedOnly.reviewPriority.factors.some((factor) => /PACK|OBFUSCAT|MINIF/.test(factor.code)),
    'source opacity must not be its own review-priority factor'
  );
}

function testDeterministicResults({ analyzeScriptPurposeInput }) {
  const input = {
    source: makeSource(
      `
        const flags = { preview: true };
        if (isFeatureEnabled('preview-panel')) {
          fetch('https://api.example.test/v1/items?token=private');
        }
      `,
      {
        label: 'deterministic.js',
        sha256: 'c'.repeat(64),
        acquiredAt: '2026-09-17T00:00:00.000Z'
      }
    ),
    scope: {
      disposition: 'in-scope',
      ownership: 'target',
      policyId: 'policy-deterministic',
      policyVersion: '1.0.0',
      matchedRuleIds: ['include-app']
    },
    runtimeObservations: [
      {
        axis: 'network',
        detail: 'A deterministic attributed request.',
        targetUrl: 'https://api.example.test/v1/items?token=private',
        method: 'GET',
        evidenceId: 'runtime-deterministic'
      }
    ]
  };

  const first = analyzeScriptPurposeInput(input);
  const second = analyzeScriptPurposeInput(structuredClone(input));
  assert.deepEqual(second, first);
  assert.equal(new Set(first.evidence.map((entry) => entry.evidenceId)).size, first.evidence.length);

  const knownEvidenceRefs = new Set(first.evidence.map((entry) => entry.evidenceId));
  const referencedEvidence = [
    ...first.transform.signals.flatMap((signal) => signal.evidenceRefs),
    ...first.purposeClaims.flatMap((claim) => claim.evidenceRefs),
    ...first.behaviorClaims.flatMap((claim) => claim.evidenceRefs),
    ...first.indicators.flatMap((indicator) => indicator.evidenceRefs),
    ...first.reviewPriority.factors.flatMap((factor) => factor.evidenceRefs)
  ];
  for (const reference of referencedEvidence) {
    assert.ok(knownEvidenceRefs.has(reference), `unknown evidence reference: ${reference}`);
  }
}

function testStageScopeGates({ analyzeScriptPurpose }) {
  const source = makeSource('const app = { ready: true };', { sha256: 'd'.repeat(64) });
  const runtimeObservations = [
    {
      axis: 'dom-ui',
      detail: 'The application shell initialized during the reviewed scenario.',
      evidenceId: 'runtime-stage-gate'
    }
  ];

  const thirdParty = analyzeScriptPurpose(source, {
    scope: { disposition: 'in-scope', ownership: 'third-party' },
    runtimeObservations
  });
  assertStage(thirdParty, 0, 'complete', 'NONE');
  assertStage(thirdParty, 2, 'complete', 'NONE');
  assertStage(thirdParty, 3, 'blocked', 'THIRD_PARTY_ACTIVE_TEST_BLOCKED');

  const needsScope = analyzeScriptPurpose(source, {
    scope: { disposition: 'review', ownership: 'target' },
    runtimeObservations
  });
  assertStage(needsScope, 3, 'blocked', 'EXPLICIT_SCOPE_REQUIRED');

  const inScope = analyzeScriptPurpose(source, {
    scope: { disposition: 'in-scope', ownership: 'target' },
    runtimeObservations
  });
  assertStage(inScope, 3, 'ready', 'NONE');

  const noRuntime = analyzeScriptPurpose(source, {
    scope: { disposition: 'in-scope', ownership: 'target' }
  });
  assertStage(noRuntime, 2, 'conditional', 'RUNTIME_EVIDENCE_REQUIRED');
  assertStage(noRuntime, 3, 'conditional', 'RUNTIME_EVIDENCE_REQUIRED');
}

function testAnalysisCaps({ analyzeScriptPurpose }, rubric) {
  assert.deepEqual(rubric.SCRIPT_ANALYSIS_DEFAULT_LIMITS, {
    maxEvidence: 160,
    maxIndicators: 80,
    maxClaims: 12,
    maxSnippetCharacters: 240
  });
  assert.deepEqual(rubric.SCRIPT_ANALYSIS_HARD_LIMITS, {
    maxEvidence: 500,
    maxIndicators: 250,
    maxClaims: 32,
    maxSnippetCharacters: 500
  });

  const runtimeObservations = Array.from({ length: 700 }, (_, index) => ({
    axis: 'network',
    detail: `${'runtime-detail '.repeat(80)}${index}`,
    targetUrl: `https://api${index}.example.test/v1/items/${index}?token=private-${index}`,
    evidenceId: `runtime-cap-${index}`
  }));
  const cappedEvidence = analyzeScriptPurpose(makeSource('const ready = true;'), {
    runtimeObservations,
    options: {
      maxEvidence: 50_000,
      maxIndicators: 50_000,
      maxClaims: 50_000,
      maxSnippetCharacters: 50_000
    }
  });
  assert.equal(cappedEvidence.evidence.length, rubric.SCRIPT_ANALYSIS_HARD_LIMITS.maxEvidence);
  assert.ok(cappedEvidence.indicators.length <= rubric.SCRIPT_ANALYSIS_HARD_LIMITS.maxIndicators);
  assert.ok(cappedEvidence.purposeClaims.length <= rubric.SCRIPT_ANALYSIS_HARD_LIMITS.maxClaims);
  assert.ok(
    cappedEvidence.evidence.every(
      (entry) =>
        (entry.detail?.length ?? 0) <= rubric.SCRIPT_ANALYSIS_HARD_LIMITS.maxSnippetCharacters &&
        (entry.snippet?.length ?? 0) <= rubric.SCRIPT_ANALYSIS_HARD_LIMITS.maxSnippetCharacters
    )
  );

  const endpointLiterals = Array.from(
    { length: 400 },
    (_, index) => `const endpoint${index} = 'https://host${index}.example.test/api/items/${index}';`
  ).join('\n');
  const cappedIndicators = analyzeScriptPurpose(makeSource(endpointLiterals), {
    options: { maxEvidence: 500, maxIndicators: 100_000 }
  });
  assert.equal(cappedIndicators.indicators.length, rubric.SCRIPT_ANALYSIS_HARD_LIMITS.maxIndicators);

  const singleItemLimits = analyzeScriptPurpose(
    makeSource("fetch('/api/items'); localStorage.setItem('draft', value);"),
    {
      options: {
        maxEvidence: 0,
        maxIndicators: 0,
        maxClaims: 0,
        maxSnippetCharacters: 0
      }
    }
  );
  assert.ok(singleItemLimits.evidence.length <= 1);
  assert.ok(singleItemLimits.indicators.length <= 1);
  assert.ok(singleItemLimits.purposeClaims.length <= 1);

  const smallSnippetLimit = 7;
  const smallSnippets = analyzeScriptPurpose(
    makeSource(`
      const feature_flags = { previewPanel: true };
      if (isFeatureEnabled('preview-panel')) {
        fetch('https://api.example.test/api/items/123456789?token=private');
        localStorage.setItem('preview-panel-state', 'enabled');
      }
    `),
    {
      runtimeObservations: [
        {
          axis: 'network',
          detail: 'An attributable network request occurred during the instrumented reload.',
          targetUrl: 'https://api.example.test/api/items/123456789?token=private',
          evidenceId: 'runtime-small-snippet-cap'
        }
      ],
      options: { maxSnippetCharacters: smallSnippetLimit }
    }
  );
  const retainedSnippets = smallSnippets.evidence
    .map((entry) => entry.snippet)
    .filter((snippet) => typeof snippet === 'string');
  assert.ok(retainedSnippets.length >= 3, 'the small-cap fixture should exercise several evidence paths');
  assert.ok(
    retainedSnippets.every((snippet) => snippet.length <= smallSnippetLimit),
    'every evidence snippet must honor the caller-supplied maximum'
  );
}

function testLatentFeatureToggleModel({ analyzeLatentFeatures }) {
  const candidates = analyzeLatentFeatures({
    textSources: [],
    structuredSources: [],
    runtimeObservedCandidates: [],
    maxCandidates: 50,
    storageEntries: [
      { area: 'localStorage', key: 'new-dashboard-feature', value: 'true' },
      {
        area: 'localStorage',
        key: 'feature-preferences',
        value: JSON.stringify({
          auth: { secretPreviewFeature: false },
          features: { safePreviewFeature: false }
        })
      },
      {
        area: 'sessionStorage',
        key: 'auth',
        value: JSON.stringify({ newAccountFeature: false })
      }
    ]
  });

  const initiallyEnabled = candidates.find((candidate) => candidate.key === 'new-dashboard-feature');
  assert.ok(initiallyEnabled, 'an enabled storage flag should be discovered');
  assert.equal(initiallyEnabled.currentValue, 'true');
  assert.equal(initiallyEnabled.suggestedValue, 'false');
  assert.equal(initiallyEnabled.enabledValue, 'true');
  assert.equal(initiallyEnabled.disabledValue, 'false');
  assert.equal(initiallyEnabled.probeable, true, 'an initially enabled flag must be switchable off');

  const initiallyDisabled = candidates.find((candidate) => candidate.key === 'safePreviewFeature');
  assert.ok(initiallyDisabled, 'a non-sensitive nested storage flag should be discovered');
  assert.equal(initiallyDisabled.enabledValue, true);
  assert.equal(initiallyDisabled.disabledValue, false);
  assert.equal(initiallyDisabled.probeable, true);
  assert.equal(
    candidates.some((candidate) => candidate.key === 'secretPreviewFeature'),
    false,
    'sensitive nested containers must not be walked'
  );
  assert.equal(
    candidates.some((candidate) => candidate.key === 'newAccountFeature'),
    false,
    'sensitive storage roots must not be walked'
  );

  const ambiguous = analyzeLatentFeatures({
    textSources: [],
    structuredSources: [],
    runtimeObservedCandidates: [],
    maxCandidates: 50,
    storageEntries: [
      { area: 'localStorage', key: 'preview_flag', value: 'false' },
      { area: 'sessionStorage', key: 'preview-flag', value: 'false' }
    ]
  });
  assert.equal(ambiguous.length, 1);
  assert.equal(ambiguous[0].normalizedKey, 'preview-flag');
  assert.equal(ambiguous[0].probeable, false);
  assert.equal(
    ambiguous[0].storageLocation,
    undefined,
    'conflicting storage locations must remain observation-only'
  );
}

function testWorkbenchPersistenceHardening(
  { analyzeScriptPurpose },
  rubric,
  { normalizeLatentFeatureWorkbenchState, javascriptTestMatchesScan }
) {
  const duplicateBody = "fetch('https://api.example.test/items?token=private');";
  const assessment = analyzeScriptPurpose(makeSource(duplicateBody, {
    sha256: 'a'.repeat(64),
    deliveryIndex: 0
  }));
  const secondAssessment = analyzeScriptPurpose(makeSource(duplicateBody, {
    sha256: 'a'.repeat(64),
    deliveryIndex: 1
  }));
  assert.notEqual(
    assessment.artifact.artifactId,
    secondAssessment.artifact.artifactId,
    'identical bytes delivered as separate artifacts need distinct identities'
  );
  const secondArtifactFingerprint =
    `${secondAssessment.artifact.artifactId}:${secondAssessment.artifact.sha256}`;
  const privateLabel =
    'asset https://alice:swordfish@cdn.example.test/app.js?token=private#fragment';
  const malformedAssessment = structuredClone(assessment);
  malformedAssessment.artifact.label = privateLabel;
  malformedAssessment.transform.complexityScore = 999;
  malformedAssessment.purposeClaims = null;
  malformedAssessment.reviewPriority = {
    scoreModel: 'untrusted-model',
    score: 999,
    band: 'low',
    isVulnerabilitySeverity: true,
    factors: []
  };

  const scan = {
    scanId: 'scan-persistence-1',
    scannedAt: '2026-09-17T00:00:00.000Z',
    tabId: 7,
    pageUrl: 'https://app.example.test/dashboard?token=private#fragment',
    origin: 'https://app.example.test',
    title: privateLabel,
    candidates: [
      {
        id: 'candidate-persistence-1',
        key: privateLabel,
        normalizedKey: privateLabel,
        currentValue: true,
        suggestedValue: false,
        confidence: 'high',
        probeable: false,
        status: 'discovered',
        controlSurface: 'bundle',
        evidence: [
          {
            sourceKind: 'bundle',
            label: privateLabel,
            detail: privateLabel
          }
        ]
      }
    ],
    newCandidateIds: [
      'candidate-persistence-1',
      'candidate-persistence-1',
      'candidate-not-retained'
    ],
    scriptAssessments: [malformedAssessment, secondAssessment],
    stats: {},
    warnings: []
  };
  const evidence = Array.from({ length: 205 }, (_, index) => ({
    evidenceId: `runtime-${index}`,
    type: index === 1 ? 'traffic-ledger-entry' : 'network-request',
    observedAt: '2026-09-17T00:00:01.000Z',
    url: `https://api.example.test/users/${index}?token=secret-${index}&mode=full#private`,
    attributes: {
      authorization: 'Bearer top-secret-value',
      responseUrl: `https://api.example.test/result/${index}?apiKey=secret-${index}`
    }
  }));
  const testRun = {
    testRunId: 'test-persistence-1',
    rubricVersion: rubric.SCRIPT_PURPOSE_RUBRIC_VERSION,
    startedAt: '2026-09-17T00:00:00.000Z',
    completedAt: '2026-09-17T00:00:02.000Z',
    tabId: 7,
    pageUrl: scan.pageUrl,
    origin: scan.origin,
    scopeDisposition: 'in-scope',
    reloadTriggered: true,
    instrumentationAvailable: true,
    instrumentationIntegrity: 'page-world-unverified',
    overallStatus: 'complete',
    scanId: scan.scanId,
    artifactIds: [
      assessment.artifact.artifactId,
      secondAssessment.artifact.artifactId,
      'dangling-artifact'
    ],
    artifactFingerprints: [
      `${assessment.artifact.artifactId}:${assessment.artifact.sha256.toUpperCase()}`,
      secondArtifactFingerprint
    ],
    cells: [
      {
        testId: 'network-static',
        stage: 'static',
        title: 'Network behavior',
        status: 'static-only',
        detail: 'Static evidence only.',
        evidenceRefs: ['runtime-0', 'dangling-evidence'],
        artifactIds: [assessment.artifact.artifactId, 'dangling-artifact']
      },
      {
        testId: 'page-world-observed',
        stage: 'instrumented',
        title: 'Page-world observation',
        status: 'observed',
        detail: 'Reported by page-world instrumentation.',
        evidenceRefs: ['runtime-0'],
        artifactIds: []
      },
      {
        testId: 'ledger-observed',
        stage: 'instrumented',
        title: 'Traffic ledger observation',
        status: 'observed',
        detail: 'Recorded by the extension traffic ledger.',
        evidenceRefs: ['runtime-1'],
        artifactIds: []
      },
      {
        testId: 'unsupported-observed',
        stage: 'instrumented',
        title: 'Unsupported observation',
        status: 'observed',
        detail: 'No retained evidence supports this cell.',
        evidenceRefs: ['dangling-evidence'],
        artifactIds: []
      }
    ],
    evidence,
    runtimeStats: { eventCount: Number.MAX_VALUE },
    gaps: []
  };

  const normalized = normalizeLatentFeatureWorkbenchState({
    lastScan: scan,
    lastJavascriptTest: testRun,
    activeProbe: {
      probeId: 'probe-persistence-1',
      createdAt: '2026-09-17T00:00:00.000Z',
      tabId: 7,
      pageUrl: 'https://alice:swordfish@app.example.test/dashboard?token=private#fragment',
      origin: 'https://app.example.test',
      changes: [
        {
          candidateId: 'candidate-'.repeat(100),
          key: 'key'.repeat(300),
          area: 'localStorage',
          storageKey: 'storage'.repeat(200),
          jsonPath: Array.from({ length: 100 }, () => 'segment'.repeat(100)),
          hadOriginalValue: true,
          originalValue: 'o'.repeat(65_536),
          originalCandidateValue: true,
          appliedValue: false
        },
        {
          candidateId: 'over-cap-restore',
          key: 'over-cap',
          area: 'sessionStorage',
          storageKey: 'over-cap',
          jsonPath: [],
          hadOriginalValue: true,
          originalValue: 'x'.repeat(65_537),
          appliedValue: true
        }
      ],
      reloadTriggered: false
    },
    lastMutation: {
      mutationId: 'mutation-persistence-1',
      observedAt: '2026-09-17T00:00:03.000Z',
      tabId: 7,
      pageUrl: 'https://alice:swordfish@app.example.test/dashboard?token=private#fragment',
      origin: 'https://app.example.test',
      candidateId: 'candidate-persistence-1',
      key: 'new-dashboard-feature',
      requestedState: 'enabled',
      previousValue: false,
      appliedValue: true,
      reloadTriggered: true,
      outcome: 'applied-with-warnings',
      codeDiff: {
        before: `const secret = 'private-value'; ${'before '.repeat(500)}`,
        after: `const feature = true; ${'after '.repeat(500)}`
      },
      pageDiff: {
        added: Array.from({ length: 125 }, (_, index) => ({
          selector: `#new-feature-${index}`,
          parentSelector: '#feature-root',
          tagName: 'DIV'
        })),
        changed: [{ selector: '#existing-feature', tagName: 'SECTION' }],
        removed: [{ selector: '#legacy-feature', parentSelector: 'main', tagName: 'ASIDE' }],
        highlightedCount: 50_000,
        truncated: true,
        limitations: Array.from({ length: 25 }, (_, index) => `limitation-${index}`)
      }
    }
  });
  const normalizedAssessment = normalized.lastScan.scriptAssessments[0];
  assert.equal(normalizedAssessment.transform.complexityScore, 100);
  assert.deepEqual(normalizedAssessment.purposeClaims, []);
  assert.equal(normalizedAssessment.reviewPriority.score, 100);
  assert.equal(normalizedAssessment.reviewPriority.band, 'urgent');
  assert.equal(normalizedAssessment.reviewPriority.scoreModel, rubric.SCRIPT_PURPOSE_SCORE_MODEL);
  assert.equal(normalizedAssessment.reviewPriority.isVulnerabilitySeverity, false);
  for (const persistedLabel of [
    normalizedAssessment.artifact.label,
    normalized.lastScan.title,
    normalized.lastScan.candidates[0].key,
    normalized.lastScan.candidates[0].normalizedKey,
    normalized.lastScan.candidates[0].evidence[0].label
  ]) {
    assert.doesNotMatch(persistedLabel, /alice|swordfish|private|fragment/i);
  }
  assert.doesNotMatch(normalized.activeProbe.pageUrl, /alice|swordfish|private|fragment/i);
  assert.equal(normalized.activeProbe.changes.length, 1);
  assert.equal(normalized.activeProbe.changes[0].candidateId.length, 256);
  assert.equal(normalized.activeProbe.changes[0].key.length, 500);
  assert.equal(normalized.activeProbe.changes[0].storageKey.length, 500);
  assert.equal(normalized.activeProbe.changes[0].jsonPath.length, 32);
  assert.ok(normalized.activeProbe.changes[0].jsonPath.every((entry) => entry.length === 500));
  assert.equal(normalized.activeProbe.changes[0].originalValue.length, 65_536);
  assert.deepEqual(normalized.lastScan.newCandidateIds, ['candidate-persistence-1']);
  assert.equal(normalized.lastScan.candidates[0].enabledValue, true);
  assert.equal(normalized.lastScan.candidates[0].disabledValue, false);

  assert.ok(normalized.lastMutation);
  assert.doesNotMatch(normalized.lastMutation.pageUrl, /alice|swordfish|private|fragment/i);
  assert.equal(normalized.lastMutation.requestedState, 'enabled');
  assert.equal(normalized.lastMutation.previousValue, false);
  assert.equal(normalized.lastMutation.appliedValue, true);
  assert.equal(normalized.lastMutation.codeDiff.before.length <= 2_000, true);
  assert.doesNotMatch(normalized.lastMutation.codeDiff.before, /private-value/i);
  assert.equal(normalized.lastMutation.pageDiff.added.length, 100);
  assert.equal(normalized.lastMutation.pageDiff.changed.length, 1);
  assert.equal(normalized.lastMutation.pageDiff.removed.length, 1);
  assert.equal(normalized.lastMutation.pageDiff.highlightedCount, 1_000);
  assert.equal(normalized.lastMutation.pageDiff.limitations.length, 20);

  const normalizedTest = normalized.lastJavascriptTest;
  assert.ok(normalizedTest, 'an exactly bound test run should survive persistence');
  assert.equal(normalizedTest.instrumentationIntegrity, 'page-world-unverified');
  assert.equal(normalizedTest.overallStatus, 'partial');
  assert.equal(normalizedTest.cells[0].status, 'static-only');
  assert.equal(
    normalizedTest.cells.find((cell) => cell.testId === 'page-world-observed').status,
    'observed-unverified'
  );
  assert.equal(
    normalizedTest.cells.find((cell) => cell.testId === 'ledger-observed').status,
    'observed'
  );
  assert.equal(
    normalizedTest.cells.find((cell) => cell.testId === 'unsupported-observed').status,
    'not-observed'
  );
  assert.equal(normalizedTest.evidence.length, 200);
  assert.deepEqual(normalizedTest.artifactIds, [
    assessment.artifact.artifactId,
    secondAssessment.artifact.artifactId
  ].sort());
  assert.deepEqual(normalizedTest.cells[0].evidenceRefs, ['runtime-0']);
  assert.deepEqual(normalizedTest.cells[0].artifactIds, [assessment.artifact.artifactId]);
  assert.doesNotMatch(normalizedTest.evidence[0].url, /secret|full|private/i);
  assert.equal(normalizedTest.evidence[0].attributes.authorization, '[redacted]');
  assert.doesNotMatch(normalizedTest.evidence[0].attributes.responseUrl, /secret/i);
  assert.equal(javascriptTestMatchesScan(normalizedTest, normalized.lastScan), true);

  const candidateCapFixture = Array.from({ length: 300 }, (_, index) => ({
    id: `candidate-cap-${index}`,
    key: `feature-cap-${index}`,
    normalizedKey: `feature-cap-${index}`,
    currentValue: false,
    suggestedValue: true,
    confidence: 'medium',
    probeable: false,
    status: 'discovered',
    controlSurface: 'bundle',
    evidence: []
  }));
  const cappedNewCandidates = normalizeLatentFeatureWorkbenchState({
    lastScan: {
      ...scan,
      candidates: candidateCapFixture,
      newCandidateIds: candidateCapFixture.map((candidate) => candidate.id),
      scriptAssessments: []
    }
  });
  assert.equal(cappedNewCandidates.lastScan.newCandidateIds.length, 200);

  const wrongFingerprint = structuredClone(testRun);
  wrongFingerprint.artifactFingerprints = [
    `${assessment.artifact.artifactId}:${'b'.repeat(64)}`,
    secondArtifactFingerprint
  ];
  assert.equal(
    normalizeLatentFeatureWorkbenchState({
      lastScan: scan,
      lastJavascriptTest: wrongFingerprint
    }).lastJavascriptTest,
    undefined
  );

  const wrongScan = structuredClone(testRun);
  wrongScan.scanId = 'scan-persistence-stale';
  assert.equal(
    normalizeLatentFeatureWorkbenchState({ lastScan: scan, lastJavascriptTest: wrongScan })
      .lastJavascriptTest,
    undefined
  );
}

function testPageSignalLabelPrivacy({ collectLatentFeaturePageSignals }) {
  const emptyStorage = {
    length: 0,
    key: () => null,
    getItem: () => null
  };
  const scripts = [
    {
      id: 'https://user:password@example.test/x?token=private#fragment',
      src: '',
      textContent: 'const inlineReady = true;'
    },
    {
      id: 'bootstrap-config',
      src: '',
      textContent: 'const configReady = true;'
    }
  ];
  scripts.item = (index) => scripts[index] ?? null;
  const originals = new Map(
    ['document', 'location', 'window', 'performance', 'NodeFilter'].map((name) => [
      name,
      Object.getOwnPropertyDescriptor(globalThis, name)
    ])
  );
  try {
    Object.defineProperties(globalThis, {
      document: {
        configurable: true,
        value: {
          contentType: 'text/javascript',
          title: 'Fixture',
          body: { textContent: 'const ready = true;' },
          scripts,
          querySelector: () => ({ textContent: 'const ready = true;' }),
          querySelectorAll: () => [],
          createTreeWalker: (root) => {
            let read = false;
            return {
              nextNode: () => {
                if (read) return null;
                read = true;
                return { nodeValue: root.textContent ?? '' };
              }
            };
          }
        }
      },
      location: {
        configurable: true,
        value: {
          href: 'https://alice:swordfish@app.example.test/assets/?token=private#fragment',
          origin: 'https://app.example.test',
          pathname: '/assets/'
        }
      },
      window: {
        configurable: true,
        value: { localStorage: emptyStorage, sessionStorage: emptyStorage }
      },
      performance: {
        configurable: true,
        value: { getEntriesByType: () => [] }
      },
      NodeFilter: {
        configurable: true,
        value: { SHOW_TEXT: 4 }
      }
    });

    const signals = collectLatentFeaturePageSignals();
    assert.equal(signals.rawDocumentSource.label, 'current JavaScript document');
    assert.doesNotMatch(signals.rawDocumentSource.label, /alice|swordfish|private|fragment/i);
    assert.equal(signals.inlineScripts[0].label, 'inline script 1');
    assert.equal(signals.inlineScripts[1].label, 'inline script #bootstrap-config');

    globalThis.document.contentType = 'text/html';
    globalThis.document.querySelector = () => undefined;
    globalThis.location.pathname = '/html-route.js';
    const htmlAtJavascriptPath = collectLatentFeaturePageSignals();
    assert.equal(
      htmlAtJavascriptPath.rawDocumentSource,
      undefined,
      'an HTML page with a .js pathname and no browser-rendered pre must not be captured as raw JavaScript'
    );
  } finally {
    for (const [name, descriptor] of originals) {
      if (descriptor) {
        Object.defineProperty(globalThis, name, descriptor);
      } else {
        delete globalThis[name];
      }
    }
  }
}

function makeSource(text, overrides = {}) {
  return {
    sourceKind: 'external',
    label: 'app.js',
    sourceUrl: 'https://app.example.test/assets/app.js',
    finalUrl: 'https://app.example.test/assets/app.js',
    text,
    contentType: 'text/javascript',
    sha256: 'f'.repeat(64),
    declaredByteLength: Buffer.byteLength(text, 'utf8'),
    acquiredAt: '2026-09-17T00:00:00.000Z',
    truncated: false,
    ...overrides
  };
}

function findPurpose(result, category) {
  const purpose = result.purposeClaims.find((claim) => claim.category === category);
  assert.ok(purpose, `missing purpose claim ${category}`);
  return purpose;
}

function findBehavior(result, axis) {
  const behavior = result.behaviorClaims.find((claim) => claim.axis === axis);
  assert.ok(behavior, `missing behavior claim ${axis}`);
  return behavior;
}

function findIndicator(result, kind) {
  const indicator = result.indicators.find((entry) => entry.kind === kind);
  assert.ok(indicator, `missing indicator ${kind}`);
  return indicator;
}

function assertCoverageGap(result, code) {
  assert.ok(result.coverage.gaps.some((gap) => gap.code === code), `missing coverage gap ${code}`);
}

function assertStage(result, stageNumber, expectedStatus, expectedReason) {
  const stage = result.testPlan.stages.find((entry) => entry.stage === stageNumber);
  assert.ok(stage, `missing stage ${stageNumber}`);
  assert.equal(stage.status, expectedStatus, `unexpected stage ${stageNumber} status`);
  assert.equal(stage.terminationReason, expectedReason, `unexpected stage ${stageNumber} reason`);
}
