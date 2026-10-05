import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

class MockChromeEvent {
  listeners = new Set();

  addListener(listener) {
    this.listeners.add(listener);
  }

  removeListener(listener) {
    this.listeners.delete(listener);
  }

  emit(details) {
    return [...this.listeners].map((listener) => listener(details));
  }
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = await mkdtemp(join(tmpdir(), 'blanche-traffic-ledger-manager-'));

try {
  await build({
    entryPoints: {
      manager: join(
        repoRoot,
        'chromium-extension/src/background/trafficLedgerManager.ts'
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

  const { TrafficLedgerManager } = await import(
    pathToFileURL(join(outputDirectory, 'manager.mjs')).href
  );

  await testPersistedStateReadFailure(TrafficLedgerManager);
  await testSessionCoverageMarkerFallback(TrafficLedgerManager);
  await testCommitBeforeRequestUsesOneContext(TrafficLedgerManager);
  await testCompletedNavigationWaitsForCommit(TrafficLedgerManager);
  await testFailedNavigationPreservesActiveTarget(TrafficLedgerManager);
  await testSameSafeUrlErrorsPreserveExactCandidate(TrafficLedgerManager);
  await testDelayedSameSafeCommitPreservesNewerCandidate(TrafficLedgerManager);
  await testStaleNavigationFailureDoesNotClobberCommit(TrafficLedgerManager);
  await testPendingNavigationSurvivesWorkerRestart(TrafficLedgerManager);
  await testRedirectRetentionAndActiveNavigationWindow(TrafficLedgerManager);
  await testRetentionAndQueryTruncation(TrafficLedgerManager);

  console.log('Traffic ledger manager tests passed.');
} finally {
  delete globalThis.chrome;
  await rm(outputDirectory, { recursive: true, force: true });
}

async function testPersistedStateReadFailure(TrafficLedgerManager) {
  const storageKey = 'test.traffic-ledger.load-failure';
  const coverageStorageKey = `${storageKey}.coverage`;
  const localValues = {};
  const sessionValues = {};
  const failingMock = createChromeMock({
    localValues,
    sessionValues,
    localGetError: new Error('simulated local storage read failure')
  });
  globalThis.chrome = failingMock.chrome;
  const errors = [];
  const failingManager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey,
    onError: (error, operation) => errors.push({ error, operation })
  });

  try {
    await failingManager.initialize();
    const ledger = await failingManager.buildExport({
      sourceSessionId: 'load-failure-test'
    });

    assert.equal(ledger.metadata.captureCoverage.truncated, true);
    assert.equal(ledger.metadata.captureCoverage.droppedEntryCount, 0);
    assert.ok(
      ledger.metadata.captureCoverage.reasonCodes.includes('PERSISTED_STATE_LOAD_FAILED')
    );
    assert.ok(errors.some(({ operation }) => operation === 'load'));
    assert.deepEqual(localValues[coverageStorageKey], {
      version: 1,
      reasonCodes: ['PERSISTED_STATE_LOAD_FAILED']
    });
  } finally {
    await failingManager.stop();
  }

  const restoredMock = createChromeMock({ localValues, sessionValues });
  globalThis.chrome = restoredMock.chrome;
  const restoredManager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey
  });
  try {
    await restoredManager.initialize();
    const restoredLedger = await restoredManager.buildExport({
      sourceSessionId: 'restored-load-failure-test'
    });
    assert.equal(restoredLedger.metadata.captureCoverage.truncated, true);
    assert.ok(
      restoredLedger.metadata.captureCoverage.reasonCodes.includes(
        'PERSISTED_STATE_LOAD_FAILED'
      ),
      'a fresh manager must restore the durable coverage marker'
    );
  } finally {
    await restoredManager.stop();
  }
}

async function testSessionCoverageMarkerFallback(TrafficLedgerManager) {
  const storageKey = 'test.traffic-ledger.session-coverage-fallback';
  const localCoverageKey = `${storageKey}.coverage`;
  const sessionCoverageKey = `${storageKey}.coverage.session`;
  const localValues = {};
  const sessionValues = {};
  const failingMock = createChromeMock({
    localValues,
    sessionValues,
    localGetError: new Error('simulated local storage read failure'),
    localSetError: new Error('simulated local coverage marker write failure')
  });
  globalThis.chrome = failingMock.chrome;
  const errors = [];
  const failingManager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey,
    onError: (error, operation) => errors.push({ error, operation })
  });
  let restoredMock;
  let restoredManager;

  try {
    await failingManager.initialize();
    assert.equal(localValues[localCoverageKey], undefined);
    assert.deepEqual(sessionValues[sessionCoverageKey], {
      version: 1,
      reasonCodes: ['PERSISTED_STATE_LOAD_FAILED']
    });
    assert.ok(
      errors.some(({ operation }) => operation === 'persist-coverage-marker-local')
    );

    restoredMock = createChromeMock({ localValues, sessionValues });
    globalThis.chrome = restoredMock.chrome;
    restoredManager = new TrafficLedgerManager({
      getScopePolicy: createScopePolicy,
      storageKey
    });
    await restoredManager.initialize();
    const ledger = await restoredManager.buildExport({
      sourceSessionId: 'session-coverage-fallback-test'
    });
    assert.equal(ledger.metadata.captureCoverage.truncated, true);
    assert.ok(
      ledger.metadata.captureCoverage.reasonCodes.includes(
        'PERSISTED_STATE_LOAD_FAILED'
      ),
      'a fresh manager must restore a load failure from the session marker fallback'
    );
  } finally {
    if (restoredManager && restoredMock) {
      globalThis.chrome = restoredMock.chrome;
      await restoredManager.stop();
    }
    globalThis.chrome = failingMock.chrome;
    await failingManager.clear();
    await failingManager.stop();
  }
}

async function testCommitBeforeRequestUsesOneContext(TrafficLedgerManager) {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey: 'test.traffic-ledger.commit-before-request',
    settings: { maxEntries: 20 }
  });

  try {
    await manager.initialize();
    const request = requestDetails({
      requestId: 'commit-before-request',
      url: 'https://target.test/early?token=private-value',
      timeStamp: 600,
      tabId: 7,
      type: 'main_frame'
    });
    mock.events.onNavigationCommitted.emit(navigationCommittedDetails(request, 601));
    mock.events.onBeforeRequest.emit(request);
    mock.events.onCompleted.emit(completedDetails(request, 602));

    const activeWindow = await manager.query({
      tabId: 7,
      targetOrigin: 'https://target.test'
    });
    assert.equal(activeWindow.observationWindowStart, new Date(600).toISOString());
    assert.equal(activeWindow.entries.length, 1);
    assert.equal(activeWindow.entries[0].endpoint.host, 'target.test');
    assert.ok(
      activeWindow.entries[0].evidence.some(
        (evidence) => evidence.id === 'commit-before-request:0'
      ),
      'the main request must be retained in the early committed document context'
    );
  } finally {
    await manager.stop();
  }
}

async function testCompletedNavigationWaitsForCommit(TrafficLedgerManager) {
  const storageKey = 'test.traffic-ledger.commit-boundary';
  const targetStorageKey = `${storageKey}.targets`;
  const sessionValues = {};
  const mock = createChromeMock({ sessionValues });
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey,
    settings: { maxEntries: 20 }
  });

  try {
    await manager.initialize();
    const establishedNavigation = requestDetails({
      requestId: 'commit-boundary-a',
      url: 'https://target.test/baseline',
      timeStamp: 700,
      tabId: 9,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(establishedNavigation);
    mock.events.onNavigationCommitted.emit(
      navigationCommittedDetails(establishedNavigation, 701)
    );
    mock.events.onCompleted.emit(completedDetails(establishedNavigation, 702));

    const completedCandidate = requestDetails({
      requestId: 'commit-boundary-b',
      url: 'https://b.test/completed-only',
      timeStamp: 800,
      tabId: 9,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(completedCandidate);
    mock.events.onCompleted.emit(completedDetails(completedCandidate, 801));
    await settleAsyncWrites();
    assert.ok(
      sessionValues[targetStorageKey]?.pendingNavigations?.['commit-boundary-b']
    );

    const stillActive = await manager.query({
      tabId: 9,
      targetOrigin: 'https://target.test'
    });
    assert.equal(
      stillActive.observationWindowStart,
      new Date(700).toISOString(),
      'webRequest completion alone must not replace the committed navigation window'
    );
    await settleAsyncWrites();
    assert.equal(
      sessionValues[targetStorageKey]?.pendingNavigations?.['commit-boundary-b'],
      undefined,
      'query must sweep a completed candidate after its no-commit TTL expires'
    );
  } finally {
    await manager.stop();
  }
}

async function testSameSafeUrlErrorsPreserveExactCandidate(TrafficLedgerManager) {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey: 'test.traffic-ledger.same-safe-url',
    settings: { maxEntries: 20 }
  });
  const startedAt = Date.now() - 1_000;

  try {
    await manager.initialize();
    const navigationA = requestDetails({
      requestId: 'same-safe-url-a',
      url: 'https://b.test/collision?token=value-a',
      timeStamp: startedAt,
      tabId: 12,
      type: 'main_frame'
    });
    const navigationB = requestDetails({
      requestId: 'same-safe-url-b',
      url: 'https://b.test/collision?token=value-b',
      timeStamp: startedAt + 100,
      tabId: 12,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(navigationA);
    mock.events.onBeforeRequest.emit(navigationB);
    mock.events.onErrorOccurred.emit({
      ...navigationA,
      timeStamp: startedAt + 200,
      fromCache: false,
      error: 'net::ERR_ABORTED'
    });
    mock.events.onNavigationError.emit(
      navigationErrorDetails(navigationA, startedAt + 201)
    );
    mock.events.onNavigationCommitted.emit(
      navigationCommittedDetails(navigationB, startedAt + 300)
    );
    mock.events.onCompleted.emit(completedDetails(navigationB, startedAt + 301));

    const activeB = await manager.query({
      tabId: 12,
      targetOrigin: 'https://b.test'
    });
    assert.equal(
      activeB.observationWindowStart,
      new Date(startedAt + 100).toISOString()
    );
    assert.equal(activeB.entries.length, 1);
    assert.ok(
      activeB.entries[0].evidence.some(
        (evidence) => evidence.id === 'same-safe-url-b:0'
      )
    );
    assert.equal(
      activeB.entries[0].evidence.some(
        (evidence) => evidence.id === 'same-safe-url-a:0'
      ),
      false,
      'A and B must not merge across committed navigation contexts'
    );
  } finally {
    await manager.stop();
  }
}

async function testFailedNavigationPreservesActiveTarget(TrafficLedgerManager) {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey: 'test.traffic-ledger.failed-navigation',
    settings: { maxEntries: 20 }
  });

  try {
    await manager.initialize();
    const establishedNavigation = requestDetails({
      requestId: 'established-navigation',
      url: 'https://target.test/baseline',
      timeStamp: 1_000,
      tabId: 11,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(establishedNavigation);
    mock.events.onNavigationCommitted.emit(
      navigationCommittedDetails(establishedNavigation, 1_001)
    );
    mock.events.onCompleted.emit(completedDetails(establishedNavigation, 1_001));

    const failedNavigation = requestDetails({
      requestId: 'failed-navigation',
      url: 'https://blocked.test/out-of-scope',
      timeStamp: 1_500,
      tabId: 11,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(failedNavigation);
    mock.events.onErrorOccurred.emit({
      ...failedNavigation,
      timeStamp: 1_501,
      fromCache: false,
      error: 'net::ERR_CONNECTION_REFUSED'
    });

    const restoredWindow = await manager.query({
      tabId: 11,
      targetOrigin: 'https://target.test'
    });
    assert.equal(
      restoredWindow.observationWindowStart,
      new Date(1_000).toISOString(),
      'failed navigation must preserve the committed navigation start'
    );
    assert.deepEqual(
      restoredWindow.entries.map((entry) => entry.endpoint.host),
      ['target.test'],
      'the failed out-of-scope navigation must not replace or enter the active ledger window'
    );
  } finally {
    await manager.stop();
  }
}

async function testDelayedSameSafeCommitPreservesNewerCandidate(TrafficLedgerManager) {
  const storageKey = 'test.traffic-ledger.delayed-same-safe-commit';
  const targetStorageKey = `${storageKey}.targets`;
  const sessionValues = {};
  const mock = createChromeMock({ sessionValues });
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey,
    settings: { maxEntries: 20 }
  });

  try {
    await manager.initialize();
    const navigationA = requestDetails({
      requestId: 'delayed-commit-a',
      url: 'https://b.test/same-template?token=value-a',
      timeStamp: 100,
      tabId: 14,
      type: 'main_frame'
    });
    const navigationB = requestDetails({
      requestId: 'delayed-commit-b',
      url: 'https://b.test/same-template?token=value-b',
      timeStamp: 200,
      tabId: 14,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(navigationA);
    mock.events.onBeforeRequest.emit(navigationB);

    mock.events.onNavigationCommitted.emit(navigationCommittedDetails(navigationA, 150));
    mock.events.onCompleted.emit(completedDetails(navigationA, 151));
    await settleAsyncWrites();
    assert.ok(
      sessionValues[targetStorageKey]?.pendingNavigations?.['delayed-commit-b'],
      'A commit must not consume the newer same-safe-URL B candidate'
    );

    mock.events.onNavigationCommitted.emit(navigationCommittedDetails(navigationB, 250));
    mock.events.onCompleted.emit(completedDetails(navigationB, 251));

    const activeB = await manager.query({
      tabId: 14,
      targetOrigin: 'https://b.test'
    });
    assert.equal(activeB.observationWindowStart, new Date(200).toISOString());
    assert.equal(activeB.entries.length, 1);
    assert.ok(
      activeB.entries[0].evidence.some(
        (evidence) => evidence.id === 'delayed-commit-b:0'
      )
    );
    assert.equal(
      activeB.entries[0].evidence.some(
        (evidence) => evidence.id === 'delayed-commit-a:0'
      ),
      false,
      'the final B window must exclude A evidence despite the shared safe endpoint'
    );
  } finally {
    await manager.stop();
  }
}

async function testStaleNavigationFailureDoesNotClobberCommit(TrafficLedgerManager) {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey: 'test.traffic-ledger.overlapping-navigation',
    settings: { maxEntries: 20 }
  });

  try {
    await manager.initialize();
    const navigationB = requestDetails({
      requestId: 'overlap-b',
      url: 'https://b.test/pending',
      timeStamp: 1_800,
      tabId: 13,
      type: 'main_frame'
    });
    const navigationC = requestDetails({
      requestId: 'overlap-c',
      url: 'https://c.test/committed',
      timeStamp: 1_900,
      tabId: 13,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(navigationB);
    mock.events.onBeforeRequest.emit(navigationC);
    mock.events.onCompleted.emit(completedDetails(navigationC, 1_901));
    mock.events.onNavigationCommitted.emit(navigationCommittedDetails(navigationC, 1_902));

    mock.events.onErrorOccurred.emit({
      ...navigationB,
      timeStamp: 1_903,
      fromCache: false,
      error: 'net::ERR_ABORTED'
    });

    const activeC = await manager.query({
      tabId: 13,
      targetOrigin: 'https://c.test'
    });
    assert.equal(activeC.observationWindowStart, new Date(1_900).toISOString());
    assert.deepEqual(
      activeC.entries.map((entry) => entry.endpoint.host),
      ['c.test'],
      'a stale B failure must not clobber the later committed C navigation'
    );
  } finally {
    await manager.stop();
  }
}

async function testPendingNavigationSurvivesWorkerRestart(TrafficLedgerManager) {
  const storageKey = 'test.traffic-ledger.worker-restart';
  const targetStorageKey = `${storageKey}.targets`;
  const localValues = {};
  const sessionValues = {};
  const firstMock = createChromeMock({ localValues, sessionValues });
  globalThis.chrome = firstMock.chrome;
  const firstManager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey,
    settings: { maxEntries: 20 }
  });
  let secondMock;
  let secondManager;

  try {
    await firstManager.initialize();
    const committedA = requestDetails({
      requestId: 'restart-a',
      url: 'https://target.test/committed',
      timeStamp: 2_200,
      tabId: 15,
      type: 'main_frame'
    });
    firstMock.events.onBeforeRequest.emit(committedA);
    firstMock.events.onNavigationCommitted.emit(navigationCommittedDetails(committedA, 2_201));
    firstMock.events.onCompleted.emit(completedDetails(committedA, 2_202));

    const pendingB = requestDetails({
      requestId: 'restart-b',
      url: 'https://b.test/pending',
      timeStamp: 2_300,
      tabId: 15,
      type: 'main_frame'
    });
    firstMock.events.onBeforeRequest.emit(pendingB);
    await settleAsyncWrites();
    assert.ok(sessionValues[targetStorageKey]?.pendingNavigations?.['restart-b']);

    secondMock = createChromeMock({ localValues, sessionValues });
    globalThis.chrome = secondMock.chrome;
    secondManager = new TrafficLedgerManager({
      getScopePolicy: createScopePolicy,
      storageKey,
      settings: { maxEntries: 20 }
    });
    await secondManager.initialize();
    secondMock.events.onErrorOccurred.emit({
      ...pendingB,
      timeStamp: 2_301,
      fromCache: false,
      error: 'net::ERR_CONNECTION_RESET'
    });

    const restoredA = await secondManager.query({
      tabId: 15,
      targetOrigin: 'https://target.test'
    });
    assert.equal(
      restoredA.observationWindowStart,
      new Date(2_200).toISOString(),
      'discarding restored pending B must leave committed A active'
    );
    await settleAsyncWrites();
    assert.equal(
      sessionValues[targetStorageKey]?.pendingNavigations?.['restart-b'],
      undefined
    );
  } finally {
    if (secondManager && secondMock) {
      globalThis.chrome = secondMock.chrome;
      await secondManager.stop();
    }
    globalThis.chrome = firstMock.chrome;
    await firstManager.stop();
  }
}

async function testRedirectRetentionAndActiveNavigationWindow(TrafficLedgerManager) {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey: 'test.traffic-ledger.redirect-window',
    settings: { maxEntries: 20 }
  });

  try {
    await manager.initialize();
    const firstHop = requestDetails({
      requestId: 'redirect-1',
      url: 'https://target.test/start',
      timeStamp: 2_000,
      tabId: 17,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(firstHop);
    mock.events.onBeforeRedirect.emit({
      ...firstHop,
      timeStamp: 2_001,
      statusCode: 302,
      statusLine: 'HTTP/1.1 302 Found',
      fromCache: false,
      redirectUrl: 'https://review.test/landing',
      responseHeaders: [{ name: 'Location', value: 'https://review.test/landing' }]
    });

    const secondHop = requestDetails({
      requestId: 'redirect-1',
      url: 'https://review.test/landing',
      timeStamp: 2_002,
      tabId: 17,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(secondHop);
    mock.events.onCompleted.emit(completedDetails(secondHop, 2_003));
    mock.events.onNavigationCommitted.emit(navigationCommittedDetails(secondHop, 2_004));

    const redirected = await manager.query({
      tabId: 17,
      targetOrigin: 'https://target.test'
    });
    assert.equal(redirected.entries.length, 2);
    assert.ok(
      redirected.entries.some(
        (entry) =>
          entry.endpoint.host === 'target.test' &&
          entry.observation.coverageGaps.includes('REDIRECT_HOP')
      )
    );
    assert.equal(
      redirected.entries.find((entry) => entry.endpoint.host === 'review.test')?.scope
        .disposition,
      'review',
      'the out-of-scope redirect destination must remain correlated to the tracked target'
    );

    const freshNavigation = requestDetails({
      requestId: 'fresh-1',
      url: 'https://target.test/fresh',
      timeStamp: 3_000,
      tabId: 17,
      type: 'main_frame'
    });
    mock.events.onBeforeRequest.emit(freshNavigation);
    mock.events.onCompleted.emit(completedDetails(freshNavigation, 3_001));
    mock.events.onNavigationCommitted.emit(
      navigationCommittedDetails(freshNavigation, 3_002)
    );

    const activeWindow = await manager.query({
      tabId: 17,
      targetOrigin: 'https://target.test'
    });
    assert.equal(activeWindow.observationWindowStart, new Date(3_000).toISOString());
    assert.equal(activeWindow.entries.length, 1);
    assert.equal(activeWindow.entries[0].endpoint.pathTemplate, '/fresh');
  } finally {
    await manager.stop();
  }
}

async function testRetentionAndQueryTruncation(TrafficLedgerManager) {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const manager = new TrafficLedgerManager({
    getScopePolicy: createScopePolicy,
    storageKey: 'test.traffic-ledger.retention',
    settings: { maxEntries: 2 }
  });

  try {
    await manager.initialize();
    for (const [index, queryName] of ['alpha', 'beta', 'gamma'].entries()) {
      const request = requestDetails({
        requestId: `retention-${queryName}`,
        url: `https://target.test/api/items?${queryName}=secret-${queryName}`,
        timeStamp: 4_000 + index * 10,
        tabId: 23,
        type: 'xmlhttprequest'
      });
      mock.events.onBeforeRequest.emit(request);
      mock.events.onCompleted.emit(completedDetails(request, request.timeStamp + 1));
    }

    const query = await manager.query({ limit: 1 });
    assert.equal(query.entries.length, 1);
    assert.equal(query.totalMatchedEntries, 2);
    assert.equal(query.truncated, true);

    const ledger = await manager.buildExport({
      sourceSessionId: 'retention-test',
      limit: 1
    });
    const coverage = ledger.metadata.captureCoverage;
    assert.equal(coverage.retainedEntryLimit, 2);
    assert.equal(coverage.droppedEntryCount, 1);
    assert.equal(coverage.availableEntryCount, 2);
    assert.equal(coverage.exportedEntryCount, 1);
    assert.equal(coverage.truncated, true);
    assert.ok(coverage.reasonCodes.includes('RETAINED_ENTRY_LIMIT_REACHED'));
    assert.ok(coverage.reasonCodes.includes('EXPORT_ENTRY_LIMIT_REACHED'));
    assert.equal(JSON.stringify(ledger).includes('secret-'), false);
  } finally {
    await manager.stop();
  }
}

function createScopePolicy() {
  return {
    policyId: 'manager-test-policy',
    version: '1',
    defaultDisposition: 'review',
    evaluation: 'highest-priority-exclude-on-tie',
    rules: [
      {
        ruleId: 'include-target',
        priority: 100,
        disposition: 'in-scope',
        source: 'operator',
        matcher: { kind: 'exact-host', hostname: 'target.test' }
      },
      {
        ruleId: 'exclude-blocked',
        priority: 100,
        disposition: 'out-of-scope',
        source: 'operator',
        matcher: { kind: 'exact-host', hostname: 'blocked.test' }
      },
      {
        ruleId: 'include-b',
        priority: 100,
        disposition: 'in-scope',
        source: 'operator',
        matcher: { kind: 'exact-host', hostname: 'b.test' }
      },
      {
        ruleId: 'include-c',
        priority: 100,
        disposition: 'in-scope',
        source: 'operator',
        matcher: { kind: 'exact-host', hostname: 'c.test' }
      }
    ]
  };
}

function requestDetails({ requestId, url, timeStamp, tabId, type }) {
  return {
    requestId,
    url,
    method: 'GET',
    frameId: 0,
    parentFrameId: -1,
    tabId,
    type,
    timeStamp
  };
}

function completedDetails(request, timeStamp) {
  return {
    ...request,
    timeStamp,
    statusCode: 200,
    statusLine: 'HTTP/1.1 200 OK',
    fromCache: false,
    responseHeaders: [
      { name: 'Content-Type', value: 'application/json' },
      { name: 'Content-Length', value: '24' }
    ]
  };
}

function navigationCommittedDetails(request, timeStamp) {
  return {
    tabId: request.tabId,
    frameId: 0,
    url: request.url,
    timeStamp,
    documentId: `document-${request.requestId}`,
    transitionType: 'link',
    transitionQualifiers: []
  };
}

function navigationErrorDetails(request, timeStamp) {
  return {
    tabId: request.tabId,
    frameId: 0,
    url: request.url,
    timeStamp,
    error: 'net::ERR_ABORTED'
  };
}

async function settleAsyncWrites() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function createChromeMock({
  localGetError,
  localSetError,
  localValues = {},
  sessionValues = {}
} = {}) {
  const events = {
    onBeforeRequest: new MockChromeEvent(),
    onBeforeSendHeaders: new MockChromeEvent(),
    onHeadersReceived: new MockChromeEvent(),
    onBeforeRedirect: new MockChromeEvent(),
    onCompleted: new MockChromeEvent(),
    onErrorOccurred: new MockChromeEvent(),
    onNavigationCommitted: new MockChromeEvent(),
    onNavigationError: new MockChromeEvent(),
    onTabRemoved: new MockChromeEvent()
  };
  return {
    events,
    chrome: {
      webRequest: {
        onBeforeRequest: events.onBeforeRequest,
        onBeforeSendHeaders: events.onBeforeSendHeaders,
        onHeadersReceived: events.onHeadersReceived,
        onBeforeRedirect: events.onBeforeRedirect,
        onCompleted: events.onCompleted,
        onErrorOccurred: events.onErrorOccurred
      },
      webNavigation: {
        onCommitted: events.onNavigationCommitted,
        onErrorOccurred: events.onNavigationError
      },
      tabs: { onRemoved: events.onTabRemoved },
      storage: {
        local: createStorageArea(localValues, localGetError, localSetError),
        session: createStorageArea(sessionValues)
      }
    }
  };
}

function createStorageArea(values, getError, setError) {
  let pendingSetError = setError;
  return {
    async get(key) {
      if (getError) {
        throw getError;
      }
      if (typeof key === 'string') {
        return Object.hasOwn(values, key) ? { [key]: values[key] } : {};
      }
      if (Array.isArray(key)) {
        return Object.fromEntries(
          key.filter((item) => Object.hasOwn(values, item)).map((item) => [item, values[item]])
        );
      }
      return { ...values };
    },
    async set(update) {
      if (pendingSetError) {
        const error = pendingSetError;
        pendingSetError = undefined;
        throw error;
      }
      Object.assign(values, update);
    },
    async remove(keys) {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        delete values[key];
      }
    }
  };
}
