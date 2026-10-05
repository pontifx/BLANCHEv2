import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = await mkdtemp(join(tmpdir(), 'blanche-site-search-fingerprint-'));

try {
  await build({
    entryPoints: [join(
      repoRoot,
      'chromium-extension/src/shared/siteSearchFingerprint.ts'
    )],
    outdir: outputDirectory,
    outExtension: { '.js': '.mjs' },
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'es2022',
    logLevel: 'silent'
  });

  const fingerprint = await import(
    pathToFileURL(join(outputDirectory, 'siteSearchFingerprint.mjs')).href
  );

  testWrongSession(fingerprint);
  testObservedResultsAndSurface(fingerprint);
  testNoResults(fingerprint);
  testMixedSignalsAndDeterministicOrder(fingerprint);
  testInconclusiveAndCoverage(fingerprint);
  testDefensiveBounds(fingerprint);

  console.log('Site search fingerprint tests passed.');
} finally {
  await rm(outputDirectory, { recursive: true, force: true });
}

function testWrongSession({ buildSiteSearchFingerprint }) {
  assert.equal(buildSiteSearchFingerprint(undefined), undefined);
  assert.equal(
    buildSiteSearchFingerprint(makeSession([], { mode: 'dork-suite' })),
    undefined
  );
}

function testObservedResultsAndSurface({ buildSiteSearchFingerprint }) {
  const session = makeSession([
    makeTask({
      category: 'javascript',
      operatorIds: ['filetype', 'exact-phrase', 'filetype'],
      status: 'completed-results',
      resultCount: 7,
      nerdSurface: makeSurface()
    })
  ]);

  const actual = buildSiteSearchFingerprint(session);
  assert.equal(actual.assessment, 'results-observed');
  assert.deepEqual(actual.totals, {
    tasks: 1,
    results: 7,
    resultTasks: 1,
    noResultTasks: 0,
    manualRequiredTasks: 0,
    failedTasks: 0,
    inProgressTasks: 0
  });
  assert.deepEqual(actual.coverage, {
    observedTasks: 1,
    terminalTasks: 1,
    pendingTasks: 0,
    coverageRate: 1,
    completionRate: 1
  });
  assert.deepEqual(actual.surface, makeSurface());
  assert.equal(actual.surface.providerFingerprint.provider, 'algolia');
  assert.deepEqual(actual.categories.map(compactSignal), [
    ['javascript', 'results-observed', 1, 7]
  ]);
  assert.deepEqual(actual.operators.map(compactSignal), [
    ['exact-phrase', 'results-observed', 1, 7],
    ['filetype', 'results-observed', 1, 7]
  ]);
  assert.equal(JSON.stringify(actual).includes('private search phrase'), false);
}

function testNoResults({ buildSiteSearchFingerprint }) {
  const actual = buildSiteSearchFingerprint(makeSession([
    makeTask({ status: 'completed-no-results', operatorIds: ['inurl'] })
  ]));
  assert.equal(actual.assessment, 'no-results-observed');
  assert.equal(actual.operators[0].assessment, 'no-results-observed');
  assert.equal(actual.totals.noResultTasks, 1);
  assert.equal(actual.totals.results, 0);
}

function testMixedSignalsAndDeterministicOrder({ buildSiteSearchFingerprint }) {
  const tasks = [
    makeTask({
      id: 'z',
      category: 'javascript',
      operatorIds: ['site', 'filetype'],
      status: 'completed-no-results'
    }),
    makeTask({
      id: 'a',
      category: 'archives',
      operatorIds: ['after', 'site'],
      status: 'completed-results',
      resultCount: 3
    })
  ];
  const forward = buildSiteSearchFingerprint(makeSession(tasks));
  const reversed = buildSiteSearchFingerprint(makeSession([...tasks].reverse()));

  assert.equal(forward.assessment, 'mixed');
  assert.deepEqual(forward.categories.map(({ id }) => id), ['archives', 'javascript']);
  assert.deepEqual(forward.operators.map(({ id }) => id), ['after', 'filetype', 'site']);
  assert.equal(forward.operators.find(({ id }) => id === 'site').assessment, 'mixed');
  assert.deepEqual(
    forward.categories.map(({ id, assessment }) => [id, assessment]),
    reversed.categories.map(({ id, assessment }) => [id, assessment])
  );
  assert.deepEqual(
    forward.operators.map(({ id, assessment }) => [id, assessment]),
    reversed.operators.map(({ id, assessment }) => [id, assessment])
  );
}

function testInconclusiveAndCoverage({ buildSiteSearchFingerprint }) {
  const actual = buildSiteSearchFingerprint(makeSession([
    makeTask({ status: 'manual-required', operatorIds: ['intitle'] }),
    makeTask({ status: 'failed', operatorIds: ['intitle'] }),
    makeTask({ status: 'running', operatorIds: ['inurl'] }),
    makeTask({ status: 'completed-no-results', operatorIds: ['site'] })
  ]));

  assert.equal(actual.assessment, 'no-results-observed');
  assert.equal(actual.operators.find(({ id }) => id === 'intitle').assessment, 'inconclusive');
  assert.equal(actual.operators.find(({ id }) => id === 'inurl').assessment, 'inconclusive');
  assert.deepEqual(actual.coverage, {
    observedTasks: 1,
    terminalTasks: 3,
    pendingTasks: 1,
    coverageRate: 0.25,
    completionRate: 0.75
  });
  assert.equal(actual.totals.manualRequiredTasks, 1);
  assert.equal(actual.totals.failedTasks, 1);
  assert.equal(actual.totals.inProgressTasks, 1);
}

function testDefensiveBounds({
  buildSiteSearchFingerprint,
  MAX_SITE_SEARCH_FINGERPRINT_TASKS
}) {
  const tasks = Array.from(
    { length: MAX_SITE_SEARCH_FINGERPRINT_TASKS + 10 },
    (_, index) => makeTask({
      id: `task-${index}`,
      category: 'custom',
      operatorIds: Array.from({ length: 55 }, (__, operatorIndex) => `op-${operatorIndex}`),
      status: 'completed-results',
      resultCount: Number.MAX_SAFE_INTEGER
    })
  );
  const actual = buildSiteSearchFingerprint(makeSession(tasks));
  assert.equal(actual.totals.tasks, MAX_SITE_SEARCH_FINGERPRINT_TASKS);
  assert.equal(actual.totals.results, 1_000_000);
  assert.equal(actual.operators.length, 50);
  assert.equal(actual.truncated, true);

  const boundedProvider = buildSiteSearchFingerprint(makeSession([
    makeTask({
      nerdSurface: {
        ...makeSurface(),
        providerFingerprint: {
          provider: 'algolia',
          label: 'A'.repeat(200),
          confidence: 'medium',
          evidence: Array.from({ length: 10 }, (_, index) => `${index}-${'B'.repeat(250)}`)
        }
      }
    })
  ])).surface.providerFingerprint;
  assert.equal(boundedProvider.label.length, 120);
  assert.equal(boundedProvider.evidence.length, 6);
  assert.ok(boundedProvider.evidence.every((entry) => entry.length <= 180));
}

function compactSignal(signal) {
  return [signal.id, signal.assessment, signal.counts.tasks, signal.counts.results];
}

function makeSession(tasks, overrides = {}) {
  return {
    id: 'session-nerd',
    label: 'NERD suite',
    createdAt: '2026-09-17T12:00:00.000Z',
    updatedAt: '2026-09-17T12:00:00.000Z',
    mode: 'nerd',
    target: 'https://example.test',
    draft: {},
    automatic: true,
    tasks,
    ...overrides
  };
}

function makeTask(overrides = {}) {
  return {
    id: 'task-1',
    sessionId: 'session-nerd',
    category: 'public-footprint',
    engineId: 'nerd',
    engineName: 'Example site search',
    mode: 'nerd',
    query: 'private search phrase',
    searchUrl: 'https://example.test/search?q=private+search+phrase',
    status: 'queued',
    createdAt: '2026-09-17T12:00:00.000Z',
    resultCount: 0,
    results: [],
    ...overrides
  };
}

function makeSurface() {
  return {
    id: 'nerd-example',
    name: 'Example site search',
    mode: 'get',
    method: 'get',
    pageUrl: 'https://example.test/',
    actionUrl: 'https://example.test/search',
    queryParam: 'q',
    providerFingerprint: {
      provider: 'algolia',
      label: 'Algolia',
      confidence: 'high',
      evidence: ['Algolia InstantSearch DOM marker']
    }
  };
}
