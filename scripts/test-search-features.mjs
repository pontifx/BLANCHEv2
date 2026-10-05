import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = await mkdtemp(join(tmpdir(), 'blanche-search-features-'));

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
}

try {
  await build({
    entryPoints: {
      catalog: join(
        repoRoot,
        'chromium-extension/src/shared/searchOperatorCatalog.ts'
      ),
      dorkSuite: join(
        repoRoot,
        'chromium-extension/src/shared/searchDorkSuite.ts'
      ),
      nerdSearch: join(
        repoRoot,
        'chromium-extension/src/shared/nerdSearch.ts'
      ),
      searchExecution: join(
        repoRoot,
        'chromium-extension/src/shared/searchExecution.ts'
      ),
      workbench: join(
        repoRoot,
        'chromium-extension/src/shared/searchWorkbench.ts'
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

  const catalog = await import(
    pathToFileURL(join(outputDirectory, 'catalog.mjs')).href
  );
  const dorkSuite = await import(
    pathToFileURL(join(outputDirectory, 'dorkSuite.mjs')).href
  );
  const nerdSearch = await import(
    pathToFileURL(join(outputDirectory, 'nerdSearch.mjs')).href
  );
  const searchExecution = await import(
    pathToFileURL(join(outputDirectory, 'searchExecution.mjs')).href
  );
  const workbench = await import(
    pathToFileURL(join(outputDirectory, 'workbench.mjs')).href
  );

  testOperatorCatalog(catalog, dorkSuite);
  testEngineSpecificDorkTranslations(catalog, dorkSuite, workbench);
  testFocusTermNormalizationAndCaps(dorkSuite, workbench);
  testDorkSuiteCapAndTargetValidation(dorkSuite, workbench);
  testPortableNerdPlan(catalog, dorkSuite, workbench);
  testNerdUrlTemplates(nerdSearch);
  testSensitiveFixedParamStripping(nerdSearch);
  testNerdProviderFingerprintPersistence(nerdSearch, searchExecution);
  testWorkbenchDefaultsAndPersistence(nerdSearch, workbench);

  console.log('Search feature tests passed.');
} finally {
  await rm(outputDirectory, { recursive: true, force: true });
}

function testOperatorCatalog(catalog, dorkSuite) {
  assert.deepEqual(catalog.CORE_WEB_SEARCH_ENGINE_IDS, [
    'google',
    'bing',
    'duckduckgo'
  ]);
  assert.equal(
    catalog.SEARCH_OPERATOR_CATALOG.lastReviewed,
    catalog.SEARCH_OPERATOR_CATALOG_LAST_REVIEWED
  );
  assert.equal(
    dorkSuite.DORK_SUITE_CATALOG_REVIEWED_AT,
    catalog.SEARCH_OPERATOR_CATALOG_LAST_REVIEWED,
    'generated suites and the visible operator catalog must share a review date'
  );

  const operators = catalog.SEARCH_OPERATOR_CATALOG.operators;
  assert.ok(operators.length > 20, 'the advanced operator catalog should remain populated');
  assert.equal(
    new Set(operators.map((operator) => operator.id)).size,
    operators.length,
    'operator IDs must be unique'
  );

  for (const operator of operators) {
    assert.ok(operator.id && operator.label && operator.description);
    assert.deepEqual(
      Object.keys(operator.engines).sort(),
      [...catalog.CORE_WEB_SEARCH_ENGINE_IDS].sort(),
      `${operator.id} must assess every core web engine`
    );
    for (const engineId of catalog.CORE_WEB_SEARCH_ENGINE_IDS) {
      const support = operator.engines[engineId];
      assert.ok(Array.isArray(support.syntax));
      assert.ok(Array.isArray(support.notes));
      assert.ok(Array.isArray(support.sourceUrls) && support.sourceUrls.length > 0);
      assert.ok(Array.isArray(support.surfaces) && support.surfaces.length > 0);
      assert.equal(typeof support.safeForGeneration, 'boolean');
      for (const sourceUrl of support.sourceUrls) {
        assert.match(sourceUrl, /^https:\/\//);
      }
      if (support.safeForGeneration) {
        assert.notEqual(support.status, 'unsupported');
        assert.ok(support.syntax.length > 0);
      }
    }
  }

  const site = catalog.getSearchOperatorById('site');
  assert.ok(site);
  assert.equal(catalog.getSearchOperatorById('missing-operator'), undefined);
  assert.equal(
    catalog.getSearchOperatorSupport(site, 'google'),
    site.engines.google
  );
  assert.equal(catalog.getSearchOperatorSupport('site', 'bing'), site.engines.bing);
  assert.equal(
    catalog.getSearchOperatorSupport('missing-operator', 'duckduckgo'),
    undefined
  );

  const safeBingFileOperators = catalog.getSearchOperatorsForEngine('bing', {
    categories: ['file'],
    statuses: ['documented'],
    surfaces: ['web'],
    safeForGenerationOnly: true
  });
  assert.ok(safeBingFileOperators.length > 0);
  assert.ok(
    safeBingFileOperators.every(
      (operator) =>
        operator.category === 'file' &&
        operator.engines.bing.status === 'documented' &&
        operator.engines.bing.safeForGeneration &&
        operator.engines.bing.surfaces.includes('web')
    )
  );

  for (const engineId of catalog.CORE_WEB_SEARCH_ENGINE_IDS) {
    const safeOperators = catalog.getSafeSearchOperatorsForEngine(engineId);
    assert.ok(safeOperators.length > 0);
    assert.ok(
      safeOperators.every((operator) =>
        catalog.isSearchOperatorSafeForGeneration(operator.id, engineId)
      )
    );
    const syntaxMatches = catalog.getSearchOperatorSyntaxForEngine(engineId, {
      surfaces: ['web'],
      safeForGenerationOnly: true
    });
    assert.ok(syntaxMatches.length >= safeOperators.length);
    assert.ok(
      syntaxMatches.every(
        (match) =>
          match.syntax.length > 0 &&
          match.support === match.operator.engines[engineId]
      )
    );
  }

  assert.equal(catalog.isSearchOperatorSafeForGeneration('plus', 'google'), false);
  assert.equal(catalog.isSearchOperatorSafeForGeneration('plus', 'bing'), true);
  assert.equal(catalog.isSearchOperatorSafeForGeneration('plus', 'duckduckgo'), true);
  assert.equal(
    catalog.getSearchOperatorSupport('and', 'duckduckgo').status,
    'unsupported'
  );
}

function testEngineSpecificDorkTranslations(catalog, dorkSuite, workbench) {
  const searchDraft = {
    ...workbench.createDefaultSearchDraft(),
    targetsText: 'https://Example.COM/a/path',
    selectedEngineIds: ['google', 'bing', 'duckduckgo']
  };
  const suiteDraft = {
    ...workbench.createDefaultDorkSuiteDraft(),
    categoryIds: ['indexed-documents', 'client-artifacts', 'recent-changes'],
    keywordsText: 'incident response, ignored fallback',
    maxQueries: 60
  };
  const plan = dorkSuite.buildDorkSuitePlan(
    searchDraft,
    suiteDraft,
    new Date('2026-09-09T12:00:00.000Z')
  );

  assert.equal(dorkSuite.validateDorkSuitePlan(plan), undefined);
  assert.deepEqual(plan.targets, ['example.com']);
  assert.equal(plan.entries.length, 36);
  assert.equal(
    plan.entries.filter((entry) => entry.query.endsWith('"incident response"')).length,
    18
  );
  assert.equal(
    plan.entries.filter((entry) => entry.query.endsWith('"ignored fallback"')).length,
    18
  );
  assert.ok(plan.entries[0].query.endsWith('"incident response"'));
  assert.ok(plan.entries[1].query.endsWith('"ignored fallback"'));
  assert.equal(new Set(plan.entries.map((entry) => entry.id)).size, plan.entries.length);

  const googleDocument = findEntry(
    plan,
    'google',
    'indexed-documents',
    (entry) => entry.query.includes('filetype:xlsx')
  );
  assert.match(googleDocument.query, /^site:example\.com filetype:xlsx confidential/);
  assert.ok(googleDocument.operatorIds.includes('filetype'));

  const googleRecent = findEntry(
    plan,
    'google',
    'recent-changes',
    (entry) => entry.query.includes('security')
  );
  assert.ok(googleRecent.query.includes('after:2025-09-09 security'));
  assert.ok(googleRecent.operatorIds.includes('after'));

  const bingDocument = findEntry(
    plan,
    'bing',
    'indexed-documents',
    (entry) => entry.query.includes('ext:xlsx')
  );
  assert.ok(bingDocument.operatorIds.includes('ext'));
  const bingClient = findEntry(
    plan,
    'bing',
    'client-artifacts',
    (entry) => entry.query.includes('sourceMappingURL')
  );
  assert.ok(bingClient.query.includes('ext:js inbody:sourceMappingURL'));
  assert.deepEqual(
    bingClient.operatorIds.filter((operatorId) => operatorId !== 'site'),
    ['ext', 'inbody']
  );
  const bingRecent = findEntry(
    plan,
    'bing',
    'recent-changes',
    (entry) => entry.query.includes('security')
  );
  assert.ok(bingRecent.query.includes('prefer:security release'));
  assert.ok(bingRecent.warnings.some((warning) => warning.includes('not a date filter')));

  const duckDuckGoClient = findEntry(
    plan,
    'duckduckgo',
    'client-artifacts',
    (entry) => entry.query.includes('sourceMappingURL')
  );
  assert.ok(duckDuckGoClient.query.includes('filetype:html "sourceMappingURL"'));
  const duckDuckGoSemantic = findEntry(
    plan,
    'duckduckgo',
    'client-artifacts',
    (entry) => entry.query.includes('feature flag')
  );
  assert.ok(duckDuckGoSemantic.query.includes('~"feature flag"'));
  assert.ok(duckDuckGoSemantic.operatorIds.includes('ddg-semantic'));
  assert.ok(
    duckDuckGoSemantic.warnings.some((warning) => warning.includes('experimental'))
  );

  const expectedHosts = {
    google: 'www.google.com',
    bing: 'www.bing.com',
    duckduckgo: 'duckduckgo.com'
  };
  for (const entry of plan.entries) {
    const searchUrl = new URL(entry.searchUrl);
    assert.equal(searchUrl.hostname, expectedHosts[entry.dialect]);
    assert.equal(searchUrl.searchParams.get('q'), entry.query);
    assert.ok(entry.warnings.length > 0);
    for (const operatorId of entry.operatorIds) {
      assert.ok(
        catalog.getSearchOperatorById(operatorId),
        `${entry.dialect} recipe references unknown operator ${operatorId}`
      );
      assert.equal(
        catalog.isSearchOperatorSafeForGeneration(operatorId, entry.dialect),
        true,
        `${entry.dialect} recipe uses unsafe operator ${operatorId}`
      );
    }
  }
}

function testFocusTermNormalizationAndCaps(dorkSuite, workbench) {
  const focusedPlan = dorkSuite.buildDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'example.com',
      selectedEngineIds: ['google']
    },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      categoryIds: ['auth-surfaces'],
      keywordsText: '  First   Phrase, first phrase; Second "Phrase" ',
      maxQueries: 60
    }
  );

  assert.deepEqual(
    focusedPlan.entries.map((entry) => entry.query),
    [
      'site:example.com intitle:"login" "First Phrase"',
      'site:example.com intitle:"login" "Second Phrase"',
      'site:example.com inurl:signin "First Phrase"',
      'site:example.com inurl:signin "Second Phrase"'
    ]
  );
  assert.ok(focusedPlan.entries[0].title.includes('First Phrase'));
  assert.ok(focusedPlan.entries[1].title.includes('Second Phrase'));
  assert.equal(
    new Set(focusedPlan.entries.map((entry) => entry.id)).size,
    focusedPlan.entries.length
  );

  const emptyFocusPlan = dorkSuite.buildDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'example.com'
    },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      categoryIds: ['api-surface'],
      keywordsText: ' \n ; , ',
      maxQueries: 60
    }
  );
  assert.deepEqual(
    emptyFocusPlan.entries.map((entry) => entry.query),
    ['site:example.com inurl:openapi', 'site:example.com inurl:graphql']
  );

  const longWord = 'x'.repeat(90);
  const boundedTermsPlan = dorkSuite.buildDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'example.com'
    },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      categoryIds: ['api-surface'],
      keywordsText: `one two three four five six seven; ${longWord}`,
      maxQueries: 60
    }
  );
  assert.equal(boundedTermsPlan.entries.length, 4);
  assert.ok(
    boundedTermsPlan.entries[0].query.endsWith('"one two three four five six"')
  );
  assert.ok(boundedTermsPlan.entries[1].query.endsWith('x'.repeat(80)));
  assert.ok(
    boundedTermsPlan.warnings.some((warning) => warning.includes('2 focus terms were shortened'))
  );

  const manyTerms = Array.from({ length: 22 }, (_, index) => `term${index}`).join('\n');
  const cappedTermsPlan = dorkSuite.buildDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'example.com'
    },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      categoryIds: ['api-surface'],
      keywordsText: manyTerms,
      maxQueries: 10
    }
  );
  assert.equal(cappedTermsPlan.entries.length, 10);
  assert.ok(
    cappedTermsPlan.warnings.some((warning) =>
      warning.includes('keyword list was capped at 20 of 22')
    )
  );
  assert.ok(
    cappedTermsPlan.warnings.some((warning) =>
      warning.includes('generated suite was capped at 10 of 40')
    )
  );
  assert.equal(
    new Set(cappedTermsPlan.entries.map((entry) => entry.id)).size,
    cappedTermsPlan.entries.length
  );
}

function testDorkSuiteCapAndTargetValidation(dorkSuite, workbench) {
  const cappedPlan = dorkSuite.buildDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'one.example; two.example',
      selectedEngineIds: ['google', 'bing', 'duckduckgo']
    },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      maxQueries: 999
    },
    new Date('2026-09-09T12:00:00.000Z')
  );
  assert.equal(cappedPlan.entries.length, 60);
  assert.ok(
    cappedPlan.warnings.some((warning) =>
      warning.includes('capped at 60 of 72 queries')
    )
  );

  const parsedTargets = workbench.parseTargets(
    'https://Example.com/path, *.example.com; %.Sub.Example.com\nnot a target'
  );
  assert.deepEqual(parsedTargets, ['example.com', 'sub.example.com']);

  const missingTargetPlan = dorkSuite.buildDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: '   \n not a target',
      selectedEngineIds: ['google']
    },
    workbench.createDefaultDorkSuiteDraft()
  );
  assert.deepEqual(missingTargetPlan.targets, []);
  assert.equal(missingTargetPlan.entries.length, 0);
  assert.equal(
    dorkSuite.validateDorkSuitePlan(missingTargetPlan),
    'Add at least one authorized target before generating a dork suite.'
  );

  const missingEnginePlan = dorkSuite.buildDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'example.com',
      selectedEngineIds: ['shodan', 'crtsh']
    },
    workbench.createDefaultDorkSuiteDraft()
  );
  assert.equal(missingEnginePlan.entries.length, 0);
  assert.ok(
    missingEnginePlan.warnings.includes(
      'Select Google, Bing, or DuckDuckGo before generating an engine suite.'
    )
  );
  assert.equal(
    dorkSuite.validateDorkSuitePlan(missingEnginePlan),
    'Select Google, Bing, or DuckDuckGo before generating an engine suite.'
  );
}

function testPortableNerdPlan(catalog, dorkSuite, workbench) {
  const plan = dorkSuite.buildPortableDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'nerd.example',
      selectedEngineIds: []
    },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      keywordsText: 'authorized review',
      maxQueries: 60
    }
  );

  assert.equal(dorkSuite.validateDorkSuitePlan(plan), undefined);
  assert.deepEqual(plan.targets, ['nerd.example']);
  assert.equal(plan.entries.length, dorkSuite.DORK_SUITE_CATEGORIES.length * 2);
  assert.deepEqual(
    new Set(plan.entries.map((entry) => entry.categoryId)),
    new Set(dorkSuite.DORK_SUITE_CATEGORIES.map((category) => category.id))
  );
  for (const entry of plan.entries) {
    assert.equal(entry.dialect, 'portable');
    assert.equal(entry.engineId, undefined);
    assert.equal(entry.searchUrl, undefined);
    assert.equal(entry.target, 'nerd.example');
    assert.deepEqual(entry.targets, ['nerd.example']);
    assert.equal(entry.query.includes('site:nerd.example'), false);
    assert.ok(entry.query.endsWith('"authorized review"'));
    assert.equal(entry.operatorIds.includes('site'), false);
    assert.ok(
      entry.warnings.some((warning) =>
        warning.includes('selected destination already defines target scope')
      )
    );
    for (const operatorId of entry.operatorIds) {
      assert.ok(
        catalog.getSearchOperatorById(operatorId),
        `portable recipe references unknown operator ${operatorId}`
      );
    }
  }
  assert.deepEqual(
    plan.entries
      .filter((entry) => entry.categoryId === 'api-surface')
      .map((entry) => entry.query),
    ['openapi "authorized review"', 'inurl:openapi "authorized review"']
  );
  assert.equal(new Set(plan.entries.map((entry) => entry.id)).size, plan.entries.length);

  const surfaceBoundPlan = dorkSuite.buildPortableDorkSuitePlan(
    {
      ...workbench.createDefaultSearchDraft(),
      targetsText: 'first.example\nsecond.example'
    },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      categoryIds: ['api-surface'],
      keywordsText: 'docs',
      maxQueries: 60
    },
    'search.example'
  );
  assert.deepEqual(surfaceBoundPlan.targets, ['search.example']);
  assert.equal(surfaceBoundPlan.entries.length, 2);
  assert.ok(surfaceBoundPlan.entries.every((entry) => entry.target === 'search.example'));

  const roundRobinPlan = dorkSuite.buildPortableDorkSuitePlan(
    { ...workbench.createDefaultSearchDraft(), targetsText: 'search.example' },
    {
      ...workbench.createDefaultDorkSuiteDraft(),
      categoryIds: ['api-surface'],
      keywordsText: 'alpha\nbeta\ngamma',
      maxQueries: 3
    }
  );
  assert.equal(roundRobinPlan.entries.length, 3);
  assert.ok(roundRobinPlan.entries.some((entry) => entry.query.endsWith('alpha')));
  assert.ok(roundRobinPlan.entries.some((entry) => entry.query.endsWith('beta')));
  assert.ok(roundRobinPlan.entries.some((entry) => entry.query.endsWith('gamma')));
  assert.ok(roundRobinPlan.warnings.some((warning) => warning.includes('distributed across 3 focus terms')));

  const missingTargetPlan = dorkSuite.buildPortableDorkSuitePlan(
    { ...workbench.createDefaultSearchDraft(), targetsText: '' },
    workbench.createDefaultDorkSuiteDraft()
  );
  assert.equal(missingTargetPlan.entries.length, 0);
  assert.ok(
    missingTargetPlan.warnings.includes(
      'Add at least one authorized target before generating a Site Search suite.'
    )
  );
}

function testNerdUrlTemplates(nerdSearch) {
  const surface = nerdSearch.createNerdSearchSurfaceFromTemplate({
    name: '  Documentation   search  ',
    urlTemplate: 'https://docs.example/search?q=%7Bquery%7D&scope=all'
  });
  assert.equal(surface.name, 'Documentation search');
  assert.equal(surface.mode, 'template');
  assert.equal(surface.method, 'get');
  assert.equal(surface.urlTemplate, 'https://docs.example/search?q={query}&scope=all');

  const query = 'site:example.com "a/b & c"';
  const searchUrl = nerdSearch.buildNerdSearchUrl(surface, `  ${query}  `);
  assert.ok(searchUrl.includes('site%3Aexample.com%20%22a%2Fb%20%26%20c%22'));
  const parsed = new URL(searchUrl);
  assert.equal(parsed.searchParams.get('q'), query);
  assert.equal(parsed.searchParams.get('scope'), 'all');

  assert.throws(
    () =>
      nerdSearch.createNerdSearchSurfaceFromTemplate({
        name: 'Missing placeholder',
        urlTemplate: 'https://docs.example/search?q=static'
      }),
    /exactly one \{query\} placeholder/
  );
  assert.throws(
    () =>
      nerdSearch.createNerdSearchSurfaceFromTemplate({
        name: 'Credentialed endpoint',
        urlTemplate: 'https://user:password@docs.example/search?q={query}'
      }),
    /exactly one \{query\} placeholder/
  );
  const sanitizedTemplate = nerdSearch.createNerdSearchSurfaceFromTemplate({
    name: 'Sanitized endpoint',
    urlTemplate: 'https://docs.example/search?q={query}&scope=all&api_key=remove-me#fragment'
  });
  assert.equal(sanitizedTemplate.urlTemplate, 'https://docs.example/search?q={query}&scope=all');
  assert.equal(JSON.stringify(sanitizedTemplate).includes('remove-me'), false);
  assert.throws(
    () =>
      nerdSearch.createNerdSearchSurfaceFromTemplate({
        name: 'Duplicate placeholder',
        urlTemplate: 'https://docs.example/search?q={query}&fallback={query}'
      }),
    /exactly one \{query\} placeholder/
  );
  assert.throws(
    () =>
      nerdSearch.createNerdSearchSurfaceFromTemplate({
        name: 'Unsafe scheme',
        urlTemplate: 'file:///tmp/search?q={query}'
      }),
    /exactly one \{query\} placeholder/
  );
  assert.throws(
    () => nerdSearch.buildNerdSearchUrl(surface, '   '),
    /cannot launch an empty query/
  );
}

function testSensitiveFixedParamStripping(nerdSearch) {
  const sensitiveValues = [
    'CSRF_VALUE_SHOULD_NOT_PERSIST',
    'TOKEN_VALUE_SHOULD_NOT_PERSIST',
    'API_KEY_VALUE_SHOULD_NOT_PERSIST',
    'SESSION_VALUE_SHOULD_NOT_PERSIST',
    'PASSWORD_VALUE_SHOULD_NOT_PERSIST',
    'AUTH_VALUE_SHOULD_NOT_PERSIST'
  ];
  const surface = nerdSearch.createNerdSearchSurface({
    id: 'candidate-search',
    name: 'Example search',
    mode: 'get',
    pageUrl: 'https://search.example/',
    actionUrl: 'https://search.example/find?existing=yes&q=old-query&token=remove-me#fragment',
    method: 'get',
    inputSelector: '#search',
    queryParam: 'q',
    fixedParams: {
      language: 'en',
      category: 'docs',
      csrf_token: sensitiveValues[0],
      accessToken: sensitiveValues[1],
      api_key: sensitiveValues[2],
      session_id: sensitiveValues[3],
      password: sensitiveValues[4],
      authorization: sensitiveValues[5]
    }
  });

  assert.deepEqual(surface.fixedParams, { language: 'en', category: 'docs' });
  const serializedSurface = JSON.stringify(surface);
  for (const value of sensitiveValues) {
    assert.equal(serializedSurface.includes(value), false);
  }

  const searchUrl = new URL(nerdSearch.buildNerdSearchUrl(surface, 'site:example.com'));
  assert.equal(searchUrl.searchParams.get('existing'), 'yes');
  assert.equal(searchUrl.hash, '');
  assert.equal(searchUrl.searchParams.getAll('q').length, 1);
  assert.equal(searchUrl.searchParams.has('token'), false);
  assert.equal(searchUrl.searchParams.get('language'), 'en');
  assert.equal(searchUrl.searchParams.get('category'), 'docs');
  assert.equal(searchUrl.searchParams.get('q'), 'site:example.com');
  for (const key of [
    'csrf_token',
    'accessToken',
    'api_key',
    'session_id',
    'password',
    'authorization'
  ]) {
    assert.equal(searchUrl.searchParams.has(key), false);
  }

  const timestamp = '2026-09-09T12:00:00.000Z';
  const normalized = nerdSearch.normalizeNerdSearchSurface({
    ...surface,
    id: 'persisted-get-surface',
    createdAt: timestamp,
    updatedAt: timestamp,
    fixedParams: {
      locale: 'en-US',
      xsrf: 'XSRF_VALUE_SHOULD_NOT_PERSIST',
      secretField: 'SECRET_VALUE_SHOULD_NOT_PERSIST'
    }
  });
  assert.ok(normalized);
  assert.deepEqual(normalized.fixedParams, { locale: 'en-US' });
  assert.equal(JSON.stringify(normalized).includes('SHOULD_NOT_PERSIST'), false);
}

function testNerdProviderFingerprintPersistence(nerdSearch, searchExecution) {
  const surface = nerdSearch.createNerdSearchSurface({
    id: 'candidate-provider',
    name: 'Provider-backed search',
    mode: 'get',
    pageUrl: 'https://search.example/',
    actionUrl: 'https://search.example/find',
    method: 'get',
    inputSelector: '#search',
    queryParam: 'q',
    fixedParams: {},
    providerFingerprint: {
      provider: 'algolia',
      label: 'Algolia',
      confidence: 'medium',
      evidence: ['Algolia InstantSearch DOM marker']
    }
  });
  assert.deepEqual(surface.providerFingerprint, {
    provider: 'algolia',
    label: 'Algolia',
    confidence: 'medium',
    evidence: ['Algolia InstantSearch DOM marker']
  });

  const snapshot = searchExecution.createNerdSearchSurfaceSnapshot(surface);
  assert.deepEqual(snapshot.providerFingerprint, surface.providerFingerprint);
  assert.equal(snapshot.inputSelector, undefined);
  assert.deepEqual(
    searchExecution.normalizeSearchExecutionState({
      settings: {},
      sessions: [{
        id: 'session-provider',
        label: 'Provider run',
        createdAt: '2026-09-17T12:00:00.000Z',
        updatedAt: '2026-09-17T12:00:00.000Z',
        mode: 'nerd',
        draft: {},
        automatic: true,
        tasks: [{
          id: 'task-provider',
          sessionId: 'session-provider',
          category: 'custom',
          engineId: 'nerd',
          engineName: 'Provider-backed search',
          mode: 'nerd',
          query: 'review',
          searchUrl: 'https://search.example/find?q=review',
          nerdSurface: snapshot,
          status: 'completed-no-results',
          createdAt: '2026-09-17T12:00:00.000Z',
          resultCount: 0,
          results: []
        }]
      }]
    }).sessions[0].tasks[0].nerdSurface.providerFingerprint,
    surface.providerFingerprint
  );
}

function testWorkbenchDefaultsAndPersistence(nerdSearch, workbench) {
  const defaults = workbench.createDefaultSearchWorkbenchState();
  assert.deepEqual(defaults.draft.selectedEngineIds, ['google']);
  assert.deepEqual(
    workbench.SEARCH_ENGINES.filter((engine) => engine.defaultSelected).map(
      (engine) => engine.id
    ),
    ['google']
  );
  assert.ok(
    workbench.SEARCH_ENGINES.some(
      (engine) =>
        engine.id === 'duckduckgo' &&
        !engine.defaultSelected &&
        engine.queryParam === 'q' &&
        engine.searchBaseUrl === 'https://duckduckgo.com/'
    )
  );
  for (const profileId of [
    'builtin-osint-public-footprint',
    'builtin-osint-documents-secrets'
  ]) {
    const profile = defaults.savedProfiles.find((entry) => entry.id === profileId);
    assert.ok(profile);
    assert.deepEqual(profile.selectedEngineIds, ['google', 'bing', 'duckduckgo']);
  }

  const fallback = workbench.normalizeSearchWorkbenchState(undefined);
  assert.deepEqual(fallback.draft.selectedEngineIds, ['google']);
  assert.deepEqual(
    fallback.dorkSuiteDraft,
    workbench.createDefaultDorkSuiteDraft()
  );

  const nerdSurface = nerdSearch.createNerdSearchSurfaceFromTemplate({
    name: 'Persisted docs search',
    urlTemplate: 'https://docs.example/search?q={query}'
  });
  const staleTimestamp = '2025-01-01T00:00:00.000Z';
  const normalized = workbench.normalizeSearchWorkbenchState({
    draft: {
      name: 'Persisted DDG draft',
      targetsText: 'example.com',
      queryText: 'intitle:login',
      selectedEngineIds: ['duckduckgo', 'google', 'duckduckgo', 'invalid-engine'],
      launchMode: 'per-target',
      openInBackground: false
    },
    dorkSuiteDraft: {
      categoryIds: ['client-artifacts', 'client-artifacts', 'not-a-category'],
      keywordsText: 'persisted keyword',
      maxQueries: 999
    },
    savedProfiles: [
      {
        id: 'builtin-osint-public-footprint',
        name: 'Stale built-in copy',
        targetsText: '',
        queryText: 'stale query',
        selectedEngineIds: ['google'],
        launchMode: 'combined',
        openInBackground: true,
        createdAt: staleTimestamp,
        updatedAt: staleTimestamp
      },
      {
        id: 'saved-ddg-only',
        name: 'Saved DDG only',
        targetsText: 'example.com',
        queryText: 'filetype:pdf',
        selectedEngineIds: ['duckduckgo', 'invalid-engine'],
        launchMode: 'combined',
        openInBackground: true,
        createdAt: staleTimestamp,
        updatedAt: staleTimestamp
      }
    ],
    customOperators: [
      {
        id: 'operator-ddg',
        label: 'DDG semantic',
        template: '~"{value}"',
        description: 'Persisted DDG operator',
        category: 'content',
        engineIds: ['duckduckgo', 'invalid-engine'],
        isCustom: true,
        createdAt: staleTimestamp,
        updatedAt: staleTimestamp
      }
    ],
    nerdSurfaces: [
      nerdSurface,
      { ...nerdSurface, name: 'Duplicate ID should be removed' },
      { id: 'invalid-surface' }
    ],
    selectedNerdSurfaceId: 'missing-surface'
  });

  assert.deepEqual(normalized.draft.selectedEngineIds, ['duckduckgo', 'google']);
  assert.equal(normalized.draft.launchMode, 'per-target');
  assert.equal(normalized.draft.openInBackground, false);
  assert.deepEqual(normalized.dorkSuiteDraft.categoryIds, ['client-artifacts']);
  assert.equal(normalized.dorkSuiteDraft.maxQueries, 60);
  assert.equal(normalized.nerdSurfaces.length, 1);
  assert.equal(normalized.selectedNerdSurfaceId, nerdSurface.id);
  assert.deepEqual(normalized.customOperators[0].engineIds, ['duckduckgo']);

  const restoredBuiltIn = normalized.savedProfiles.find(
    (profile) => profile.id === 'builtin-osint-public-footprint'
  );
  assert.ok(restoredBuiltIn);
  assert.notEqual(restoredBuiltIn.name, 'Stale built-in copy');
  assert.deepEqual(restoredBuiltIn.selectedEngineIds, [
    'google',
    'bing',
    'duckduckgo'
  ]);
  const savedDuckDuckGoProfile = normalized.savedProfiles.find(
    (profile) => profile.id === 'saved-ddg-only'
  );
  assert.ok(savedDuckDuckGoProfile);
  assert.deepEqual(savedDuckDuckGoProfile.selectedEngineIds, ['duckduckgo']);

  assert.deepEqual(
    workbench.normalizeSearchDraft({
      selectedEngineIds: ['bing', 'crtsh'],
      launchMode: 'combined',
      openInBackground: true
    }).selectedEngineIds,
    ['bing', 'crtsh']
  );
  assert.deepEqual(
    workbench.normalizeSearchDraft({ selectedEngineIds: ['invalid-engine'] })
      .selectedEngineIds,
    ['google']
  );
}

function findEntry(plan, dialect, categoryId, predicate) {
  const entry = plan.entries.find(
    (candidate) =>
      candidate.dialect === dialect &&
      candidate.categoryId === categoryId &&
      predicate(candidate)
  );
  assert.ok(entry, `missing ${dialect} ${categoryId} dork entry`);
  return entry;
}
