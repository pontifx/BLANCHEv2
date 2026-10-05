import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = await mkdtemp(join(tmpdir(), 'blanche-traffic-ledger-'));

try {
  await build({
    entryPoints: {
      traffic: join(repoRoot, 'chromium-extension/src/shared/trafficLedger.ts'),
      scope: join(repoRoot, 'chromium-extension/src/shared/scopePolicy.ts')
    },
    outdir: outputDirectory,
    outExtension: { '.js': '.mjs' },
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'es2022',
    logLevel: 'silent'
  });

  const traffic = await import(pathToFileURL(join(outputDirectory, 'traffic.mjs')).href);
  const scope = await import(pathToFileURL(join(outputDirectory, 'scope.mjs')).href);

  testCanonicalization(traffic);
  testScopePatterns(traffic, scope);
  testScopeEvaluation(traffic, scope);
  testScoring(traffic);
  await testLedgerAggregation(traffic, scope);
  await testSchemaContract();

  console.log('Traffic ledger tests passed.');
} finally {
  await rm(outputDirectory, { recursive: true, force: true });
}

function testCanonicalization(traffic) {
  const endpoint = traffic.canonicalizeTrafficEndpoint(
    'https://USER_VALUE_829:PASS_VALUE_928@Example.COM:443/api/users/123/token/PATH_SECRET_927' +
      '?z=QUERY_VALUE_111&apiKey=QUERY_VALUE_222&a=QUERY_VALUE_333#FRAGMENT_VALUE_444',
    'get'
  );

  assert.deepEqual(endpoint, {
    scheme: 'https',
    host: 'example.com',
    port: 443,
    method: 'GET',
    pathTemplate: '/api/users/{int}/token/{secret}',
    queryParameterNames: ['a', 'apiKey', 'z']
  });
  const serialized = JSON.stringify(endpoint);
  for (const secret of [
    'USER_VALUE_829',
    'PASS_VALUE_928',
    'PATH_SECRET_927',
    'QUERY_VALUE_111',
    'QUERY_VALUE_222',
    'QUERY_VALUE_333',
    'FRAGMENT_VALUE_444'
  ]) {
    assert.equal(serialized.includes(secret), false, `canonical endpoint retained ${secret}`);
  }
  assert.throws(
    () => traffic.canonicalizeTrafficEndpoint('file:///tmp/secret', 'GET'),
    /Unsupported traffic URL scheme/
  );

  const privatePath = traffic.canonicalizeTrafficEndpoint(
    'https://example.com/patients/alice@example.com/reset/short-reset-code',
    'GET'
  );
  assert.equal(privatePath.pathTemplate, '/patients/{secret}/reset/{secret}');
  assert.equal(JSON.stringify(privatePath).includes('alice@example.com'), false);
  assert.equal(JSON.stringify(privatePath).includes('short-reset-code'), false);
  assert.equal(
    traffic.canonicalizeTrafficEndpoint('https://example.com/users/search', 'GET').pathTemplate,
    '/users/search',
    'known route actions remain useful taxonomy labels'
  );
}

function testScopePatterns(traffic, scope) {
  const policy = scope.parseScopePatternLines({
    policyId: 'engagement-alpha',
    version: '7',
    includeText: [
      'GET api.example.com',
      '[POST] *.example.com',
      'https://example.com/api?token=URL_PATTERN_SECRET',
      '10.2.9.44/16'
    ].join('\n'),
    excludeText: 'DELETE blocked.example.com',
    defaultDisposition: 'unknown'
  });

  assert.equal(policy.defaultDisposition, 'unknown');
  assert.deepEqual(policy.rules.map((rule) => rule.matcher.kind), [
    'exact-host',
    'wildcard-subdomain',
    'url-prefix',
    'ipv4-cidr',
    'exact-host'
  ]);
  assert.deepEqual(policy.rules[0].methods, ['GET']);
  assert.equal(policy.rules[1].matcher.baseHostname, 'example.com');
  assert.equal(policy.rules[2].matcher.prefix, 'https://example.com/api');
  assert.equal(policy.rules[3].matcher.cidr, '10.2.0.0/16');
  assert.equal(JSON.stringify(policy).includes('URL_PATTERN_SECRET'), false);

  const formatted = scope.formatScopePolicyPatterns(policy);
  assert.match(formatted.includeText, /^GET api\.example\.com/m);
  assert.match(formatted.includeText, /^POST \*\.example\.com/m);
  assert.match(formatted.includeText, /^https:\/\/example\.com\/api/m);
  assert.match(formatted.includeText, /^10\.2\.0\.0\/16/m);
  assert.equal(formatted.excludeText, 'DELETE blocked.example.com');
  assert.equal(formatted.reviewText, '');

  const structuredPolicy = scope.normalizeScopePolicy({
    policyId: 'structured-scope',
    version: '3',
    defaultDisposition: 'unknown',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [
      {
        ruleId: 'include-api-origin',
        priority: 100,
        disposition: 'in-scope',
        source: 'operator',
        matcher: {
          kind: 'exact-host',
          hostname: 'api.example.com',
          schemes: ['https'],
          ports: [8443]
        },
        methods: ['GET']
      },
      {
        ruleId: 'exclude-tracking-subdomains',
        priority: 100,
        disposition: 'out-of-scope',
        source: 'operator',
        matcher: {
          kind: 'wildcard-subdomain',
          baseHostname: 'tracking.example.com',
          schemes: ['https', 'wss'],
          ports: [443, 8443]
        }
      },
      {
        ruleId: 'review-internal-network',
        priority: 100,
        disposition: 'review',
        source: 'operator',
        matcher: {
          kind: 'ipv4-cidr',
          cidr: '10.40.0.0/16',
          schemes: ['http', 'https'],
          ports: [8080, 8443]
        },
        methods: ['POST']
      }
    ]
  });
  const structuredPatterns = scope.formatScopePolicyPatterns(structuredPolicy);
  assert.equal(
    structuredPatterns.includeText,
    'GET api.example.com schemes=https ports=8443'
  );
  assert.equal(
    structuredPatterns.excludeText,
    '*.tracking.example.com schemes=https,wss ports=443,8443'
  );
  assert.equal(
    structuredPatterns.reviewText,
    'POST 10.40.0.0/16 schemes=http,https ports=8080,8443'
  );

  const roundTrippedPolicy = scope.parseScopePatternLines({
    policyId: structuredPolicy.policyId,
    version: structuredPolicy.version,
    includeText: structuredPatterns.includeText,
    excludeText: structuredPatterns.excludeText,
    reviewText: structuredPatterns.reviewText,
    defaultDisposition: structuredPolicy.defaultDisposition
  });
  assert.deepEqual(
    roundTrippedPolicy.rules.map(({ disposition, matcher, methods }) => ({
      disposition,
      matcher,
      methods
    })),
    structuredPolicy.rules.map(({ disposition, matcher, methods }) => ({
      disposition,
      matcher,
      methods
    }))
  );

  for (const sample of [
    ['https://api.example.com:8443/users', 'GET', 'in-scope'],
    ['https://api.example.com/users', 'GET', 'unknown'],
    ['http://api.example.com:8443/users', 'GET', 'unknown'],
    ['https://pixel.tracking.example.com/report', 'GET', 'out-of-scope'],
    ['https://10.40.7.9:8443/jobs', 'POST', 'review'],
    ['https://10.40.7.9:8443/jobs', 'GET', 'unknown']
  ]) {
    const [rawUrl, method, expectedDisposition] = sample;
    const evaluationInput = {
      rawUrl,
      endpoint: traffic.canonicalizeTrafficEndpoint(rawUrl, method)
    };
    assert.equal(
      scope.evaluateTrafficScope(structuredPolicy, evaluationInput).disposition,
      expectedDisposition
    );
    assert.equal(
      scope.evaluateTrafficScope(roundTrippedPolicy, evaluationInput).disposition,
      expectedDisposition
    );
  }

  const capturePatterns = scope.formatScopePolicyPatterns(
    scope.createCaptureTargetScopePolicy('https://capture.example.com:9443/start')
  );
  assert.equal(capturePatterns.includeText, 'capture.example.com schemes=https ports=9443');
  assert.equal(capturePatterns.reviewText, '');

  const persistedPolicy = scope.normalizeScopePolicy({
    policyId: 'persisted-structured-policy',
    version: '11',
    defaultDisposition: 'review',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [
      {
        ruleId: 'include-001',
        priority: 275,
        disposition: 'in-scope',
        source: 'imported',
        matcher: {
          kind: 'exact-host',
          hostname: 'admin.example.com',
          schemes: ['https'],
          ports: [443, 8443]
        },
        methods: ['GET', 'POST'],
        note: 'Approved administrative origin.'
      },
      {
        ruleId: 'burp-review-rule',
        priority: 80,
        disposition: 'review',
        source: 'burp',
        matcher: { kind: 'url-prefix', prefix: 'https://example.com/manual-review' },
        methods: ['PATCH', 'PUT'],
        note: 'Retain grouped methods for manual review.'
      }
    ]
  });
  const clonedPolicy = scope.cloneScopePolicy(persistedPolicy);
  assert.deepEqual(clonedPolicy, persistedPolicy);
  assert.notEqual(clonedPolicy.rules, persistedPolicy.rules);
  assert.notEqual(clonedPolicy.rules[0].matcher, persistedPolicy.rules[0].matcher);
  assert.notEqual(clonedPolicy.rules[0].methods, persistedPolicy.rules[0].methods);

  const savedPolicy = scope.appendScopePatternLines({
    policy: clonedPolicy,
    version: '12',
    includeText: 'DELETE cleanup.example.com schemes=https ports=443'
  });
  assert.equal(savedPolicy.version, '12');
  assert.deepEqual(savedPolicy.rules.slice(0, persistedPolicy.rules.length), persistedPolicy.rules);
  assert.deepEqual(savedPolicy.rules[2], {
    ruleId: 'include-001-2',
    priority: 100,
    disposition: 'in-scope',
    source: 'operator',
    matcher: {
      kind: 'exact-host',
      hostname: 'cleanup.example.com',
      schemes: ['https'],
      ports: [443]
    },
    methods: ['DELETE'],
    note: undefined
  });

  const emptyConstraints = scope.normalizeScopePolicy({
    policyId: 'empty-constraints',
    version: '1',
    defaultDisposition: 'review',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [
      {
        ruleId: 'empty',
        priority: 1,
        disposition: 'in-scope',
        source: 'operator',
        matcher: { kind: 'exact-host', hostname: 'example.com', schemes: [], ports: [] },
        methods: []
      }
    ]
  });
  assert.equal(emptyConstraints.rules[0].methods, undefined);
  assert.equal(emptyConstraints.rules[0].matcher.schemes, undefined);
  assert.equal(emptyConstraints.rules[0].matcher.ports, undefined);

  const cidrInput = {
    endpoint: traffic.canonicalizeTrafficEndpoint('https://10.2.7.8/a', 'GET'),
    rawUrl: 'https://10.2.7.8/a'
  };
  assert.equal(scope.scopeRuleMatches(policy.rules[3], cidrInput), true);
  assert.throws(
    () =>
      scope.parseScopePatternLines({
        policyId: 'bad',
        version: '1',
        includeText: '999.1.1.1/77',
        excludeText: ''
      }),
    /Invalid include scope pattern/
  );
  assert.throws(
    () =>
      scope.parseScopePatternLines({
        policyId: 'bad-url-constraint',
        version: '1',
        includeText: 'https://example.com/api schemes=https',
        excludeText: ''
      }),
    /URL-prefix rules carry their scheme and port in the URL/
  );

  const validPolicy = {
    policyId: 'validation-policy',
    version: '1',
    defaultDisposition: 'review',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [
      {
        ruleId: 'valid-rule',
        priority: 100,
        disposition: 'in-scope',
        source: 'operator',
        matcher: { kind: 'exact-host', hostname: 'example.com' }
      }
    ]
  };
  assert.throws(
    () => scope.normalizeScopePolicy({ ...validPolicy, defaultDisposition: 'in-scope' }),
    /invalid default disposition/
  );
  assert.throws(
    () =>
      scope.normalizeScopePolicy({
        ...validPolicy,
        rules: [validPolicy.rules[0], { ...validPolicy.rules[0] }]
      }),
    /duplicate ruleId valid-rule/
  );
  assert.throws(
    () =>
      scope.normalizeScopePolicy({
        ...validPolicy,
        rules: [{ ...validPolicy.rules[0], source: 'browser-guess' }]
      }),
    /invalid source/
  );
  assert.throws(
    () =>
      scope.normalizeScopePolicy({
        ...validPolicy,
        rules: [{ ...validPolicy.rules[0], matcher: { kind: 'regex', value: '.*' } }]
      }),
    /invalid matcher kind/
  );
}

function testScopeEvaluation(traffic, scope) {
  const rawUrl = 'https://sub.example.com/private/report';
  const input = {
    endpoint: traffic.canonicalizeTrafficEndpoint(rawUrl, 'GET'),
    rawUrl,
    evaluatedAt: '2026-09-03T12:00:00.000Z'
  };
  const tiedPolicy = {
    policyId: 'tie-policy',
    version: '1',
    defaultDisposition: 'unknown',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [
      {
        ruleId: 'include-subdomains',
        priority: 100,
        disposition: 'in-scope',
        source: 'operator',
        matcher: { kind: 'wildcard-subdomain', baseHostname: 'example.com' },
        methods: ['GET']
      },
      {
        ruleId: 'exclude-private',
        priority: 100,
        disposition: 'out-of-scope',
        source: 'operator',
        matcher: { kind: 'url-prefix', prefix: 'https://sub.example.com/private' }
      }
    ]
  };

  const decision = scope.evaluateTrafficScope(tiedPolicy, input);
  assert.equal(decision.disposition, 'out-of-scope');
  assert.deepEqual(decision.matchedRuleIds, ['exclude-private', 'include-subdomains']);
  assert.ok(decision.reasonCodes.includes('SCOPE_EXCLUDE_EQUAL_PRIORITY_TIE'));

  const apexUrl = 'https://example.com/private/report';
  assert.equal(
    scope.scopeRuleMatches(tiedPolicy.rules[0], {
      endpoint: traffic.canonicalizeTrafficEndpoint(apexUrl, 'GET'),
      rawUrl: apexUrl
    }),
    false,
    'wildcard subdomain rules must not match the apex host'
  );
  assert.equal(
    scope.scopeRuleMatches(tiedPolicy.rules[0], {
      endpoint: traffic.canonicalizeTrafficEndpoint(rawUrl, 'POST'),
      rawUrl
    }),
    false,
    'method constraints must be enforced'
  );

  const unknown = scope.evaluateTrafficScope(
    { ...tiedPolicy, rules: [] },
    {
      endpoint: traffic.canonicalizeTrafficEndpoint('https://other.test/x', 'GET'),
      rawUrl: 'https://other.test/x',
      evaluatedAt: '2026-09-03T12:00:00.000Z'
    }
  );
  assert.equal(unknown.disposition, 'unknown');
  assert.equal(unknown.basis, 'default');
  assert.equal(unknown.confidence, 'low');
}

function testScoring(traffic) {
  const settings = traffic.defaultTrafficLedgerSettings('https://example.com/');
  const sensitiveInput = {
    url: 'https://example.com/api/admin/login',
    observedAt: '2026-09-03T12:00:00.000Z',
    source: 'chromium-web-request',
    method: 'POST',
    requestHeaderNames: ['Authorization: Bearer SCORE_HEADER_SECRET'],
    responseHeaderNames: ['Set-Cookie: SCORE_COOKIE_SECRET'],
    requestBodyFieldNames: ['password=SCORE_BODY_SECRET']
  };
  const taxonomy = traffic.classifyTrafficObservation(
    sensitiveInput,
    settings.scopePolicy,
    settings.originContext
  );
  assert.ok(taxonomy.classification.roles.includes('api'));
  assert.ok(taxonomy.classification.roles.includes('authentication'));
  assert.ok(taxonomy.classification.roles.includes('administration'));
  assert.ok(taxonomy.classification.dataClasses.includes('credential'));
  assert.ok(taxonomy.classification.dataClasses.includes('session'));
  assert.equal(taxonomy.classification.access, 'authenticated');

  const priority = traffic.scoreTrafficObservation(sensitiveInput, taxonomy.classification);
  assert.equal(priority.score, 100);
  assert.equal(priority.band, 'urgent');
  assert.ok(priority.factors.some((factor) => factor.code === 'STATE_CHANGING'));
  assert.ok(priority.factors.some((factor) => factor.code === 'SENSITIVE_DATA'));

  const staticInput = {
    url: 'https://example.com/assets/app.js',
    observedAt: '2026-09-03T12:00:00.000Z',
    source: 'chromium-performance',
    method: 'GET'
  };
  const staticTaxonomy = traffic.classifyTrafficObservation(
    staticInput,
    settings.scopePolicy,
    settings.originContext
  );
  const staticPriority = traffic.scoreTrafficObservation(staticInput, staticTaxonomy.classification);
  assert.equal(staticPriority.score, 0);
  assert.equal(staticPriority.band, 'low');

  const cookieInput = {
    url: 'https://example.com/collect',
    observedAt: '2026-09-03T12:00:00.000Z',
    source: 'chromium-web-request',
    method: 'GET',
    responseHeaderNames: ['Set-Cookie: COOKIE_VALUE_MUST_NOT_SURVIVE']
  };
  const cookieTaxonomy = traffic.classifyTrafficObservation(
    cookieInput,
    settings.scopePolicy,
    settings.originContext
  );
  const cookiePriority = traffic.scoreTrafficObservation(cookieInput, cookieTaxonomy.classification);
  assert.equal(cookieTaxonomy.classification.roles.includes('authentication'), false);
  assert.equal(cookieTaxonomy.classification.confidence, 'medium');
  assert.equal(cookiePriority.evidenceConfidence, 'high');
  assert.equal(cookiePriority.classificationConfidence, 'medium');
  assert.equal(cookiePriority.factors.some((factor) => factor.code === 'AUTHENTICATION'), false);
}

async function testLedgerAggregation(traffic, scope) {
  const settings = {
    scopePolicy: scope.parseScopePatternLines({
      policyId: 'ledger-policy',
      version: '1',
      includeText: 'example.com',
      excludeText: '',
      defaultDisposition: 'unknown'
    }),
    originContext: { targetOrigin: 'https://example.com' }
  };
  const common = {
    observedAt: '2026-09-03T12:00:00.000Z',
    method: 'POST',
    source: 'chromium-web-request',
    statusCode: 200,
    contentType: 'application/json',
    requestHeaderNames: ['Authorization: Bearer AGG_HEADER_SECRET', 'X-Trace-Id'],
    responseHeaderNames: ['Set-Cookie: AGG_COOKIE_SECRET'],
    requestBodyFieldNames: ['password: AGG_BODY_SECRET', 'email'],
    bytes: { transfer: 100, encoded: 80, decoded: 120 },
    evidence: [
      {
        kind: 'browser-request',
        id: 'request-1',
        source: 'webRequest',
        observedAt: '2026-09-03T12:00:00.000Z'
      }
    ]
  };
  const observations = [
    {
      ...common,
      url:
        'https://AGG_USER_SECRET:AGG_PASS_SECRET@example.com/api/users/123' +
        '?token=AGG_QUERY_SECRET_ONE&filter=AGG_FILTER_SECRET#AGG_FRAGMENT_SECRET'
    },
    {
      ...common,
      url: 'https://example.com/api/users/456?filter=different&token=AGG_QUERY_SECRET_TWO',
      observedAt: '2026-09-03T12:00:05.000Z',
      source: 'chromium-performance',
      statusCode: 201,
      requestHeaderNames: ['Cookie: AGG_REQUEST_COOKIE_SECRET'],
      requestBodyFieldNames: ['card=AGG_CARD_SECRET'],
      bytes: { transfer: 50, encoded: 40, decoded: 60 },
      evidence: []
    },
    {
      ...common,
      url: 'https://example.com/api/users/999?filter=third&token=third',
      method: 'GET',
      observedAt: '2026-09-03T12:00:10.000Z'
    }
  ];
  const input = {
    sourceSessionId: 'session-1',
    ledgerId: 'ledger-test',
    generatedAt: '2026-09-03T12:01:00.000Z',
    observationWindowStart: '2026-09-03T11:55:00.000Z',
    observationWindowBasis: 'retained-last-seen',
    settings,
    observations
  };
  const ledger = await traffic.buildTrafficLedger(input);
  assert.equal(ledger.kind, 'blanche.traffic-ledger');
  assert.equal(ledger.schemaVersion, '1.0.0');
  const ledgerWithCoverage = {
    ...ledger,
    metadata: {
      ...ledger.metadata,
      captureCoverage: {
        retainedEntryLimit: 1000,
        persistedByteLimit: 3000000,
        droppedEntryCount: 2,
        retentionLossScope: 'store-wide-conservative',
        availableEntryCount: ledger.entries.length,
        exportedEntryCount: ledger.entries.length,
        truncated: true,
        reasonCodes: ['RETAINED_ENTRY_LIMIT_REACHED']
      }
    }
  };
  const jsonlRecords = traffic
    .serializeTrafficLedgerJsonl(ledgerWithCoverage)
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line));
  assert.equal(jsonlRecords.length, ledger.entries.length + 1);
  assert.equal(jsonlRecords[0].recordType, 'blanche.traffic-ledger.metadata');
  assert.equal(jsonlRecords[0].ledger.metadata.captureCoverage.truncated, true);
  assert.equal(
    jsonlRecords[0].ledger.metadata.captureCoverage.retentionLossScope,
    'store-wide-conservative'
  );
  assert.ok(
    jsonlRecords.slice(1).every(
      (record) =>
        record.recordType === 'blanche.traffic-ledger.entry' &&
        record.ledgerId === ledger.metadata.ledgerId &&
        typeof record.entry?.entryId === 'string'
    )
  );
  assert.equal(ledger.metadata.observationWindowStart, '2026-09-03T11:55:00.000Z');
  assert.equal(ledger.metadata.observationWindowBasis, 'retained-last-seen');
  assert.deepEqual(ledger.dataHandling.pathHandling, {
    model: 'blanche.path-template.v1',
    recognizedIdentifiersTemplated: true,
    unrecognizedPathSegmentsIncluded: true,
    residualIdentifierRisk: true
  });
  assert.equal(ledger.entries.length, 2);
  assert.equal(ledger.summary.entryCount, 2);
  assert.equal(ledger.summary.byScope['in-scope'], 2);

  const postEntry = ledger.entries.find((entry) => entry.endpoint.method === 'POST');
  assert.ok(postEntry);
  assert.equal(postEntry.observation.count, 2);
  assert.deepEqual(postEntry.observation.statusCodes, [200, 201]);
  assert.deepEqual(postEntry.observation.sources, [
    'chromium-performance',
    'chromium-web-request'
  ]);
  assert.deepEqual(postEntry.observation.requestHeaderNames, [
    'authorization',
    'cookie',
    'x-trace-id'
  ]);
  assert.deepEqual(postEntry.observation.responseHeaderNames, ['set-cookie']);
  assert.deepEqual(postEntry.observation.requestBodyFieldNames, ['card', 'email', 'password']);
  assert.deepEqual(postEntry.observation.bytes, { transfer: 150, encoded: 120, decoded: 180 });
  assert.equal(postEntry.priority.band, 'urgent');

  const eligible = traffic.queryTrafficLedger(ledger.entries, {
    scope: ['in-scope'],
    minimumScore: 75,
    roles: ['api']
  });
  assert.equal(eligible.length, 1);
  assert.equal(eligible[0].endpoint.method, 'POST');

  const serialized = JSON.stringify(ledger);
  for (const secret of [
    'AGG_USER_SECRET',
    'AGG_PASS_SECRET',
    'AGG_HEADER_SECRET',
    'AGG_COOKIE_SECRET',
    'AGG_BODY_SECRET',
    'AGG_QUERY_SECRET_ONE',
    'AGG_QUERY_SECRET_TWO',
    'AGG_FILTER_SECRET',
    'AGG_FRAGMENT_SECRET',
    'AGG_REQUEST_COOKIE_SECRET',
    'AGG_CARD_SECRET'
  ]) {
    assert.equal(serialized.includes(secret), false, `ledger retained ${secret}`);
  }

  const rebuilt = await traffic.buildTrafficLedger(input);
  assert.deepEqual(
    rebuilt.entries.map((entry) => entry.entryId),
    ledger.entries.map((entry) => entry.entryId),
    'endpoint identities must be deterministic'
  );

  const boundedHighStatus = await traffic.buildTrafficLedgerEntry(
    { ...common, url: 'https://example.com/status/high', statusCode: 5000 },
    settings
  );
  const boundedLowStatus = await traffic.buildTrafficLedgerEntry(
    { ...common, url: 'https://example.com/status/low', statusCode: -4 },
    settings
  );
  const missingInvalidStatus = await traffic.buildTrafficLedgerEntry(
    { ...common, url: 'https://example.com/status/invalid', statusCode: Number.NaN },
    settings
  );
  assert.deepEqual(boundedHighStatus.observation.statusCodes, [999]);
  assert.deepEqual(boundedLowStatus.observation.statusCodes, [0]);
  assert.deepEqual(missingInvalidStatus.observation.statusCodes, []);
  assert.ok(missingInvalidStatus.observation.coverageGaps.includes('STATUS_UNAVAILABLE'));
}

async function testSchemaContract() {
  const ledgerSchema = JSON.parse(
    await readFile(
      join(repoRoot, 'shared-schema/schema/blanche-traffic-ledger.schema.json'),
      'utf8'
    )
  );
  const exportSchema = JSON.parse(
    await readFile(join(repoRoot, 'shared-schema/schema/blanche-export.schema.json'), 'utf8')
  );
  const burpBridgeDescriptor = JSON.parse(
    await readFile(
      join(repoRoot, 'chromium-extension/src/modules/burpBridge/descriptor.json'),
      'utf8'
    )
  );

  assert.equal(ledgerSchema.properties.kind.const, 'blanche.traffic-ledger');
  assert.equal(ledgerSchema.properties.schemaVersion.const, '1.0.0');
  assert.ok(ledgerSchema.required.includes('scopePolicy'));
  assert.ok(ledgerSchema.required.includes('dataHandling'));
  assert.ok(ledgerSchema.$defs.observation.required.includes('requestHeaderNames'));
  assert.ok(ledgerSchema.$defs.observation.required.includes('responseHeaderNames'));
  assert.ok(ledgerSchema.$defs.observation.required.includes('requestBodyFieldNames'));
  assert.ok(ledgerSchema.$defs.dataHandling.required.includes('pathHandling'));
  assert.equal(
    ledgerSchema.$defs.dataHandling.properties.pathHandling.properties.model.const,
    'blanche.path-template.v1'
  );
  assert.equal(
    ledgerSchema.$defs.metadata.properties.observationWindowBasis.const,
    'retained-last-seen'
  );
  assert.equal(
    ledgerSchema.$defs.metadata.properties.captureCoverage.$ref,
    '#/$defs/captureCoverage'
  );
  for (const property of [
    'retainedEntryLimit',
    'persistedByteLimit',
    'droppedEntryCount',
    'retentionLossScope',
    'availableEntryCount',
    'exportedEntryCount',
    'truncated',
    'reasonCodes'
  ]) {
    assert.ok(
      ledgerSchema.$defs.captureCoverage.required.includes(property),
      `capture coverage requires ${property}`
    );
  }
  assert.equal(
    ledgerSchema.$defs.captureCoverage.properties.retentionLossScope.const,
    'store-wide-conservative'
  );
  assert.equal(exportSchema.properties.schemaVersion.const, '1.1.0');
  assert.ok(exportSchema.required.includes('trafficLedger'));
  assert.equal(
    exportSchema.properties.trafficLedger.$ref,
    'https://blanche.dev/schema/blanche-traffic-ledger-v1.json'
  );
  assert.equal(
    burpBridgeDescriptor.exporters.find((exporter) => exporter.id === 'json-v1')?.schemaVersion,
    '1.1.0'
  );
}
