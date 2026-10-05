import childProcess from 'node:child_process';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const extensionDir = path.join(rootDir, 'chromium-extension');
const workSummaryDir = path.join(rootDir, 'WorkSummary');
const LOOPBACK_HOST = '127.0.0.1';
const LOOPBACK_PATH = '/api/blanche/ingest';
const LOOPBACK_OSINT_SEED_PATH = '/api/blanche/osint/seed';
const DEFAULT_LOOPBACK_PORT = 47625;

let latestIngestedExport;
let latestIngestedSeed;
let latestNerdPostSubmission;
let latestNerdDynamicSubmission;
let ingestOptionsCount = 0;
const ingestContentTypes = [];

async function main({
  tearSheetOnly = false,
  targetUrlControlsOnly = false,
  siteSearchOnly = false
} = {}) {
  const chromePath = await findChromePath();
  if (!chromePath) {
    throw new Error(
      'Chrome or Edge was not found. Set CHROME_PATH to the browser executable and rerun this smoke test.'
    );
  }

  const userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'blanche-bridge-profile-'));
  const downloadDir = path.join(userDataDir, 'Downloads');
  await prepareChromeProfile(userDataDir, downloadDir);
  const testServer = createTestTargetServer();
  const reviewScopeServer = createScopeReviewServer();
  const externalIngestUrl = process.env.BLANCHE_SMOKE_EXTERNAL_INGEST_URL;
  const externalSeedUrl =
    process.env.BLANCHE_SMOKE_EXTERNAL_OSINT_SEED_URL ??
    (externalIngestUrl
      ? new URL(LOOPBACK_OSINT_SEED_PATH, externalIngestUrl).toString()
      : undefined);
  const ingestServer = externalIngestUrl ? undefined : createIngestServer();
  let chromeProcess;

  try {
    const testPort = await listen(testServer, LOOPBACK_HOST, 0);
    const reviewScopePort = await listen(reviewScopeServer, LOOPBACK_HOST, 0);
    const debugPort = await getFreePort();
    const testOrigin = `http://${LOOPBACK_HOST}:${testPort}`;
    const reviewScopeOrigin = `http://${LOOPBACK_HOST}:${reviewScopePort}`;
    const testUrl = `${testOrigin}/`;
    const ingestPort = ingestServer
      ? await listenPreferred(ingestServer, LOOPBACK_HOST, DEFAULT_LOOPBACK_PORT)
      : undefined;
    const ingestUrl =
      externalIngestUrl ?? `http://${LOOPBACK_HOST}:${ingestPort}${LOOPBACK_PATH}`;
    const osintSeedUrl =
      externalSeedUrl ?? `http://${LOOPBACK_HOST}:${ingestPort}${LOOPBACK_OSINT_SEED_PATH}`;

    chromeProcess = launchChrome(chromePath, {
      debugPort,
      extensionDir,
      userDataDir,
      testUrl
    });

    const browserClient = await connectToBrowser(debugPort);
    try {
      const extensionId = await findExtensionId(browserClient, debugPort, userDataDir);
      const extensionPageUrl = `chrome-extension://${extensionId}/dist/sidepanel.html`;
      const { targetId } = await browserClient.send('Target.createTarget', {
        url: extensionPageUrl
      });
      const extensionPageClient = await connectToTarget(debugPort, targetId);
      try {
        await extensionPageClient.send('Runtime.enable');
        await extensionPageClient.send('Page.enable');
        const workflowResult = await evaluateJson(extensionPageClient, buildRunActionExpression({
          testOrigin,
          reviewScopeOrigin,
          ingestUrl,
          osintSeedUrl,
          tearSheetOnly,
          targetUrlControlsOnly,
          siteSearchOnly
        }));

        if (targetUrlControlsOnly) {
          verifyTargetUrlControlsResult(workflowResult);
          const screenshotPath = await captureWorkflowScreenshot(
            extensionPageClient,
            'target-url-controls-smoke.png'
          );
          const narrowScreenshotPath = await captureNarrowTargetUrlControlsScreenshot(
            extensionPageClient
          );
          console.log(
            [
              'BLANCHE target URL controls smoke passed.',
              'Disclosure: initially closed, exact URL revealed',
              'Clipboard actions: URL, parameters, GET, constructed form POST',
              `Screenshot: ${screenshotPath}`,
              `Narrow screenshot: ${narrowScreenshotPath}`
            ].join('\n')
          );
          return;
        }

        if (tearSheetOnly) {
          const downloads = await waitForTearSheetDownloads(downloadDir);
          const verification = verifyTearSheetOnlyResult(workflowResult, testOrigin, downloads);
          const screenshotPath = await captureDynamicTearSheetScreenshot(extensionPageClient);
          console.log(
            [
              'BLANCHE tear sheet smoke passed.',
              `Target: ${verification.hostname}`,
              `Artifacts: ${verification.artifactCount}`,
              `Browser-only artifacts: ${verification.browserOnlyArtifactCount}`,
              `Provenance: observed=${verification.provenance.observed}, inferred=${verification.provenance.inferred}, unavailable=${verification.provenance.unavailable}`,
              `Limitations: ${verification.limitationCount}`,
              `Downloads: ${downloads.html.name}, ${downloads.json.name}`,
              `Screenshot: ${screenshotPath}`
            ].join('\n')
          );
          return;
        }

        if (siteSearchOnly) {
          verifySiteSearchOnlyResult(workflowResult);
          const screenshotPath = await captureWorkflowScreenshot(
            extensionPageClient,
            'site-search-workflow-smoke.png'
          );
          console.log(
            [
              'BLANCHE Site Search smoke passed.',
              'Default engine: Google',
              'Selector: highlight and top-frame picker',
              'Plan: two terms, four round-robin probes, selected surface host',
              'Result: parsed tasks and aggregate behavior fingerprint',
              `Screenshot: ${screenshotPath}`
            ].join('\n')
          );
          return;
        }

        if (ingestServer) {
          await waitFor(
            () => latestIngestedExport,
            15000,
            100,
            'the loopback ingest endpoint to receive a BLANCHE export'
          );
          await waitFor(
            () => latestIngestedSeed,
            15000,
            100,
            'the loopback OSINT seed endpoint to receive a BLANCHE seed'
          );
          assert(ingestOptionsCount === 0, 'Burp and OSINT handoffs do not send CORS preflight requests.');
          assert(
            ingestContentTypes.length >= 2 && ingestContentTypes.every((value) => value.startsWith('text/plain')),
            'Burp and OSINT handoffs use a CORS-simple text payload.'
          );
        }

        const receivedExport = ingestServer ? latestIngestedExport : workflowResult.bridgeCollect.export;
        const receivedSeed = ingestServer ? latestIngestedSeed : undefined;
        const verification = verifyReceivedExport(receivedExport, workflowResult.bridgeCollect);
        const workflowVerification = verifyWorkflowResult(workflowResult, receivedSeed);
        const searchReportDownloads = await waitForTearSheetDownloads(downloadDir);
        const nerdPostObservation = verifyNerdPostSubmission(
          workflowResult,
          latestNerdPostSubmission
        );
        const nerdDynamicObservation = verifyNerdDynamicSubmission(
          workflowResult,
          latestNerdDynamicSubmission
        );
        verifySearchFeatureDownloads(workflowResult, searchReportDownloads);
        const preservedSearchReportPaths = await preserveSearchReportDownloads(
          searchReportDownloads
        );
        const searchReportArtifactPath = await writeSearchReportArtifact(workflowResult, {
          nerdPostObservation,
          nerdDynamicObservation,
          preservedSearchReportPaths
        });
        const javascriptAnalysisArtifactPath = await writeJavascriptAnalysisArtifact(
          workflowResult,
          preservedSearchReportPaths
        );
        await verifyNarrowTrafficTableLayout(extensionPageClient);
        const screenshotPath = await captureWorkflowScreenshot(extensionPageClient);
        const featureSwitchboardScreenshots = await captureJavascriptAnalysisScreenshot(
          extensionPageClient
        );
        const searchFeatureScreenshots = await captureSearchFeatureScreenshots(extensionPageClient);
        const correlatedReportScreenshotPath = await captureDynamicTearSheetScreenshot(
          extensionPageClient,
          'blanche-search-report-smoke.png'
        );
        const tearSheetScreenshotPath = await captureTearSheetScreenshot(browserClient, debugPort);
        console.log(
          [
            'BLANCHE extension workflow smoke passed.',
            `Chrome: ${chromePath}`,
            `Test page: ${testUrl}`,
            `${ingestServer ? 'Loopback ingest' : 'External Burp ingest'}: ${ingestUrl}`,
            `${ingestServer ? 'Loopback OSINT seed' : 'External Burp OSINT seed'}: ${osintSeedUrl}`,
            `Artifacts: ${receivedExport.summary.artifactCount}`,
            `Traffic endpoints: ${verification.trafficEntryCount}`,
            `Chromium-only categories: ${formatCounts(verification.chromiumOnlyCounts)}`,
            `Passive warnings: ${workflowVerification.passiveWarningCount}`,
            `Tear sheet artifacts: ${workflowVerification.reportArtifactCount}`,
            `Tear sheet limitations: ${workflowVerification.reportLimitationCount}`,
            `Documents acquired: ${workflowVerification.acquiredDocumentCount}`,
            `OSINT related hosts: ${workflowVerification.relatedHostCount}`,
            `Latent features: ${workflowVerification.latentFeatureCount}`,
            `Interest bookmarks learned: ${workflowVerification.interestBookmarkCount}`,
            `Search tabs verified: ${workflowVerification.searchTabCount}`,
            'Narrow traffic table: 360px stacked layout verified',
            `Console screenshot: ${screenshotPath}`,
            `Feature Switchboard result screenshot: ${featureSwitchboardScreenshots.result}`,
            `Feature Switchboard controls screenshot: ${featureSwitchboardScreenshots.controls}`,
            `JavaScript analysis trace: ${javascriptAnalysisArtifactPath}`,
            `Dork Suite screenshot: ${searchFeatureScreenshots.dorkSuite}`,
            `NERD mode screenshot: ${searchFeatureScreenshots.nerdMode}`,
            `Operator catalog screenshot: ${searchFeatureScreenshots.operatorCatalog}`,
            `Search-correlated report screenshot: ${correlatedReportScreenshotPath}`,
            `Search report excerpt: ${searchReportArtifactPath}`,
            `Full search report HTML: ${preservedSearchReportPaths.html}`,
            `Full search report JSON: ${preservedSearchReportPaths.json}`,
            `Tear sheet screenshot: ${tearSheetScreenshotPath}`
          ].join('\n')
        );
      } finally {
        extensionPageClient.close();
      }
    } finally {
      browserClient.close();
    }
  } finally {
    await stopChrome(chromeProcess, userDataDir);
    testServer.close();
    reviewScopeServer.close();
    ingestServer?.close();
    await removeDirectoryWithRetry(userDataDir);
  }
}

async function writeJavascriptAnalysisArtifact(workflowResult, preservedReportPaths) {
  const report = workflowResult.report?.payload;
  const scan = report?.correlatedEvidence?.latentFeatureScan;
  const test = report?.correlatedEvidence?.javascriptTest;
  const analysis = workflowResult.latentFeatures?.javascriptAnalysis;
  const artifact = {
    kind: 'blanche.javascript-analysis-smoke-report',
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    target: report?.target,
    rubricVersion: scan?.scriptAssessments?.[0]?.rubricVersion,
    staticAnalysis: {
      rawDocumentAssessmentPresent: analysis?.rawDocumentAssessmentPresent === true,
      passiveAssessmentCount: analysis?.passiveAssessmentCount ?? 0,
      passiveAppAssessmentPresent: analysis?.passiveAppAssessmentPresent === true,
      passiveReloadCountDelta: analysis?.passiveReloadCountDelta,
      queuedPassiveStartupSerialized: analysis?.queuedPassiveStartupSerialized === true,
      multiCandidateRecoveryRetained: analysis?.multiCandidateRecoveryRetained === true
    },
    featureSwitchboard: {
      lateDiscoveryStatus: workflowResult.latentFeatures?.lateDiscoveryStatus,
      newFeatureFlashVerified:
        workflowResult.latentFeatures?.newFeatureFlashVerified === true,
      onOffControlsPresent: workflowResult.latentFeatures?.onOffControlsPresent === true,
      enableStatus: workflowResult.latentFeatures?.enableStatus,
      disableStatus: workflowResult.latentFeatures?.disableStatus,
      secondEnableStatus: workflowResult.latentFeatures?.secondEnableStatus,
      codeDiffVerified: workflowResult.latentFeatures?.codeDiffVerified === true,
      pageAdditionVerified: workflowResult.latentFeatures?.pageAdditionVerified === true,
      pageRemovalVerified: workflowResult.latentFeatures?.pageRemovalVerified === true,
      activeChangeCountBeforeRestore:
        workflowResult.latentFeatures?.activeChangeCountBeforeRestore ?? 0,
      exactContainerRestore: workflowResult.latentFeatures?.exactContainerRestore === true
    },
    startupObservation: {
      actionStatus: analysis?.startupActionStatus,
      testRunId: analysis?.startupTestRunId,
      overallStatus: test?.overallStatus,
      scopeDisposition: analysis?.startupScopeDisposition,
      reloadCountDelta: analysis?.startupReloadCountDelta,
      instrumentationAvailable: analysis?.startupInstrumentationAvailable === true,
      instrumentationIntegrity: analysis?.startupInstrumentationIntegrity,
      sourceBindingMatches: analysis?.sourceBindingMatches === true,
      fingerprintCount: test?.artifactFingerprints?.length ?? 0,
      evidenceRecordCount: analysis?.evidenceRecordCount ?? 0,
      trafficEvidenceRecordCount:
        test?.evidence?.filter((entry) => entry.type === 'traffic-ledger-entry').length ?? 0,
      allCellEvidenceRefsResolve: analysis?.allCellEvidenceRefsResolve === true,
      runtimeStats: analysis?.runtimeStats,
      observedCellIds: analysis?.observedCellIds ?? [],
      unverifiedObservedCellIds: analysis?.unverifiedObservedCellIds ?? []
    },
    reportCorrelation: {
      scriptAssessmentCount: analysis?.reportScriptAssessmentCount ?? 0,
      javascriptTestRunId: analysis?.reportJavascriptTestRunId,
      hasJavascriptContext: analysis?.reportHasJavascriptContext === true,
      fullReportHtml: path.basename(preservedReportPaths.html),
      fullReportJson: path.basename(preservedReportPaths.json)
    }
  };
  await fs.mkdir(workSummaryDir, { recursive: true });
  const outputPath = path.join(workSummaryDir, 'javascript-analysis-verification.json');
  await fs.writeFile(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
  return outputPath;
}

async function writeSearchReportArtifact(
  workflowResult,
  { nerdPostObservation, nerdDynamicObservation, preservedSearchReportPaths }
) {
  const report = workflowResult.report?.payload;
  const searchSessions = report?.correlatedEvidence?.searchSessions ?? [];
  const artifact = {
    kind: 'blanche.search-feature-smoke-report',
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    target: report?.target,
    reportMetadata: report?.metadata,
    operatorCatalogRowCount: workflowResult.search?.operatorCatalogRowCount ?? 0,
    dorkSuite: workflowResult.search?.dorkSuite,
    nerdSuite: workflowResult.search?.nerdSuite,
    nerdPostSuite: workflowResult.search?.nerdPostSuite,
    nerdDynamicSuite: workflowResult.search?.nerdDynamicSuite,
    nerdTemplateSuite: workflowResult.search?.nerdTemplateSuite,
    transportObservations: {
      nerdPost: nerdPostObservation,
      nerdDynamic: nerdDynamicObservation
    },
    fullReportArtifacts: {
      html: path.basename(preservedSearchReportPaths.html),
      json: path.basename(preservedSearchReportPaths.json)
    },
    reportedSearchSessions: searchSessions
  };
  await fs.mkdir(workSummaryDir, { recursive: true });
  const outputPath = path.join(workSummaryDir, 'search-feature-smoke-report.json');
  await fs.writeFile(outputPath, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
  return outputPath;
}

async function preserveSearchReportDownloads(downloads) {
  await fs.mkdir(workSummaryDir, { recursive: true });
  const htmlPath = path.join(workSummaryDir, 'search-feature-full-report.html');
  const jsonPath = path.join(workSummaryDir, 'search-feature-full-report.json');
  await Promise.all([
    fs.writeFile(htmlPath, downloads.html.contents, 'utf8'),
    fs.writeFile(jsonPath, downloads.json.contents, 'utf8')
  ]);
  return { html: htmlPath, json: jsonPath };
}

async function findChromePath() {
  const envCandidates = [
    process.env.CHROME_PATH,
    process.env.CHROMIUM_PATH,
    process.env.EDGE_PATH
  ].filter(Boolean);
  const installRoots = [
    process.env.PROGRAMFILES,
    process.env['PROGRAMFILES(X86)'],
    process.env.LOCALAPPDATA
  ].filter(Boolean);

  const candidates = [
    ...envCandidates,
    ...installRoots.flatMap((root) => [
      path.join(root, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(root, 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
      path.join(root, 'Chromium', 'Application', 'chrome.exe')
    ])
  ];

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // Keep looking.
    }
  }

  return undefined;
}

async function prepareChromeProfile(userDataDir, downloadDir) {
  const defaultProfileDir = path.join(userDataDir, 'Default');
  await fs.mkdir(defaultProfileDir, { recursive: true });
  await fs.mkdir(downloadDir, { recursive: true });
  await fs.writeFile(
    path.join(defaultProfileDir, 'Preferences'),
    JSON.stringify({
      download: {
        default_directory: downloadDir,
        directory_upgrade: true,
        prompt_for_download: false
      },
      safebrowsing: {
        enabled: false
      },
      profile: {
        default_content_setting_values: {
          automatic_downloads: 1
        }
      }
    }),
    'utf8'
  );
}

function createTestTargetServer() {
  return http.createServer((request, response) => {
    const url = new URL(request.url ?? '/', `http://${request.headers.host}`);
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "img-src 'self' blob: data:",
      "worker-src 'self' blob:",
      "connect-src 'self'",
      "style-src 'self' 'unsafe-inline'"
    ].join('; ');

    if (url.pathname === '/') {
      sendText(response, 200, 'text/html; charset=utf-8', htmlPage(), {
        'Content-Security-Policy': csp,
        'Cache-Control': 'no-store'
      });
      return;
    }

    if (url.pathname === '/search') {
      const query = url.searchParams.get('q')?.trim() ?? '';
      const resultPath = `/docs/readme.txt?from=nerd&q=${encodeURIComponent(query)}`;
      sendText(
        response,
        200,
        'text/html; charset=utf-8',
        `<!doctype html>
          <html lang="en">
            <head><meta charset="utf-8" /><title>Smoke site search</title></head>
            <body>
              <main>
                <h1>Search results</h1>
                <article class="search-result" data-testid="search-result">
                  <a class="result-link" href="${resultPath}">Local indexed smoke result</a>
                  <p>Matched the submitted query: ${escapeHtmlForSmokePage(query)}</p>
                </article>
              </main>
            </body>
          </html>`,
        {
          'Content-Security-Policy': csp,
          'Cache-Control': 'no-store'
        }
      );
      return;
    }

    if (url.pathname === '/search/post' && request.method === 'POST') {
      let body = '';
      request.setEncoding('utf8');
      request.on('data', (chunk) => {
        body = `${body}${chunk}`.slice(0, 16_384);
      });
      request.on('end', () => {
        const params = new URLSearchParams(body);
        const query = params.get('keyword')?.trim() ?? '';
        latestNerdPostSubmission = {
          method: request.method,
          pathname: url.pathname,
          contentType: String(request.headers['content-type'] ?? ''),
          query,
          corpus: params.get('corpus') ?? '',
          sensitiveControlSubmitted: params.has('csrf_token')
        };
        const resultPath = `/docs/readme.txt?from=nerd-post&q=${encodeURIComponent(query)}`;
        sendText(
          response,
          200,
          'text/html; charset=utf-8',
          `<!doctype html>
            <html lang="en">
              <head><meta charset="utf-8" /><title>Smoke POST site search</title></head>
              <body>
                <main>
                  <h1>POST search results</h1>
                  <article class="search-result" data-testid="post-search-result">
                    <a class="result-link" href="${resultPath}">Local POST-indexed smoke result</a>
                    <p>Matched the submitted POST query: ${escapeHtmlForSmokePage(query)}</p>
                  </article>
                </main>
              </body>
            </html>`,
          {
            'Content-Security-Policy': csp,
            'Cache-Control': 'no-store'
          }
        );
      });
      return;
    }

    if (url.pathname === '/search/dynamic') {
      const query = url.searchParams.get('q')?.trim() ?? '';
      latestNerdDynamicSubmission = {
        method: request.method,
        pathname: url.pathname,
        query,
        view: url.searchParams.get('view') ?? ''
      };
      const resultPath = `/docs/readme.txt?from=nerd-dynamic&q=${encodeURIComponent(query)}`;
      sendText(
        response,
        200,
        'text/html; charset=utf-8',
        `<!doctype html>
          <html lang="en">
            <head><meta charset="utf-8" /><title>Smoke dynamic site search</title></head>
            <body>
              <main>
                <h1>Dynamic search results</h1>
                <article class="search-result" data-testid="dynamic-search-result">
                  <a class="result-link" href="${resultPath}">Local JavaScript-widget smoke result</a>
                  <p>Matched the JavaScript-submitted query: ${escapeHtmlForSmokePage(query)}</p>
                </article>
              </main>
            </body>
          </html>`,
        {
          'Content-Security-Policy': csp,
          'Cache-Control': 'no-store'
        }
      );
      return;
    }

    if (url.pathname === '/app.js') {
      sendText(response, 200, 'text/javascript; charset=utf-8', appScript(), {
        'Cache-Control': 'no-store'
      });
      return;
    }

    if (url.pathname === '/feature-config.json') {
      sendJson(response, 200, {
        features: {
          remotePreviewPanel: false,
          navigationVariant: 'control'
        },
        assignments: [
          {
            flagKey: 'pairedResponseFeature',
            enabled: false
          }
        ],
        opaqueAssignments: {
          '8f14e45fceea167a': 'c9f0f895fb98ab91'
        }
      });
      return;
    }

    if (url.pathname === '/frame.html') {
      sendText(
        response,
        200,
        'text/html; charset=utf-8',
        '<!doctype html><title>BLANCHE smoke frame</title><a href="/docs/readme.txt">Frame document</a>',
        {
          'Content-Security-Policy': csp,
          'Cache-Control': 'no-store'
        }
      );
      return;
    }

    if (url.pathname === '/worker.js') {
      sendText(
        response,
        200,
        'text/javascript; charset=utf-8',
        "self.onmessage = () => self.postMessage('pong');\n",
        {
          'Cache-Control': 'no-store'
        }
      );
      return;
    }

    if (url.pathname === '/sw.js') {
      sendText(
        response,
        200,
        'text/javascript; charset=utf-8',
        [
          "self.addEventListener('install', (event) => event.waitUntil(self.skipWaiting()));",
          "self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));",
          "self.addEventListener('fetch', () => {});"
        ].join('\n'),
        {
          'Cache-Control': 'no-store',
          'Service-Worker-Allowed': '/'
        }
      );
      return;
    }

    if (url.pathname === '/cached.txt') {
      sendText(response, 200, 'text/plain; charset=utf-8', 'cached body', {
        'Cache-Control': 'no-store'
      });
      return;
    }

    if (url.pathname === '/docs/report.pdf') {
      sendText(
        response,
        200,
        'application/pdf',
        [
          '%PDF-1.4',
          '1 0 obj << /Type /Catalog >> endobj',
          'BLANCHE smoke report contains internal admin portal notes.',
          'Contact https://portal.example.test/admin for follow-up.',
          'The token smoke-secret-token is intentionally synthetic.',
          '%%EOF'
        ].join('\n'),
        {
          'Cache-Control': 'no-store',
          'Content-Disposition': 'attachment; filename="blanche-smoke-report.pdf"'
        }
      );
      return;
    }

    if (url.pathname === '/docs/auto-capture.csv') {
      sendText(
        response,
        200,
        'text/csv; charset=utf-8',
        'name,url,notes\nsecret,https://files.example.test/archive,internal token smoke-secret-token\n',
        {
          'Cache-Control': 'no-store',
          'Content-Disposition': 'attachment; filename="auto-capture.csv"'
        }
      );
      return;
    }

    if (url.pathname === '/docs/readme.txt') {
      sendText(
        response,
        200,
        'text/plain; charset=utf-8',
        'Readme for BLANCHE smoke. credential marker and https://docs.example.test/help\n',
        {
          'Cache-Control': 'no-store'
        }
      );
      return;
    }

    sendText(response, 404, 'text/plain; charset=utf-8', 'not found');
  });
}

function createScopeReviewServer() {
  return http.createServer((_request, response) => {
    sendText(
      response,
      200,
      'text/html; charset=utf-8',
      '<!doctype html><html lang="en"><title>BLANCHE scope review probe</title><body>Scope review probe</body></html>',
      {
        'Cache-Control': 'no-store'
      }
    );
  });
}

function htmlPage() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>BLANCHE bridge smoke target</title>
    <script type="module" src="/app.js"></script>
  </head>
  <body>
    <h1>BLANCHE bridge smoke target</h1>
    <nav>
      <a href="/docs/report.pdf">Quarterly report PDF</a>
      <a href="/docs/auto-capture.csv">Auto capture CSV</a>
      <a href="/docs/readme.txt">Readme text</a>
      <a href="https://login.example.test/sign-in">Related login host</a>
      <a href="https://cdn.example.test/assets/app.js">Related CDN host</a>
    </nav>
    <form id="site-search" role="search" action="/search" method="get">
      <label for="site-search-input">Search this smoke site</label>
      <input id="site-search-input" type="search" name="q" placeholder="Search smoke content" />
      <select name="section" aria-label="Search section">
        <option value="all" selected>All content</option>
      </select>
      <input type="hidden" name="csrf_token" value="must-not-be-captured" />
      <button id="site-search-submit" type="submit">Search</button>
    </form>
    <form id="site-post-search" role="search" action="/search/post" method="post">
      <label for="site-post-search-input">Search the smoke archive with POST</label>
      <input id="site-post-search-input" type="search" name="keyword" placeholder="Search smoke archive" />
      <select name="corpus" aria-label="Archive corpus">
        <option value="knowledge" selected>Knowledge base</option>
      </select>
      <input type="hidden" name="csrf_token" value="must-not-be-reported" />
      <button id="site-post-search-submit" type="submit">Search archive</button>
    </form>
    <section id="site-dynamic-search" role="search" aria-label="JavaScript widget search">
      <label for="site-dynamic-search-input">Search with the JavaScript widget</label>
      <input id="site-dynamic-search-input" type="search" name="q" placeholder="Search dynamic content" />
      <button id="site-dynamic-search-submit" type="button">Search dynamically</button>
    </section>
    <form action="https://forms.example.test/intake" method="post">
      <input name="email" value="operator@example.test" />
    </form>
    <iframe src="/frame.html" title="Smoke frame"></iframe>
  </body>
</html>
`;
}

function escapeHtmlForSmokePage(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function appScript() {
  return `
const sleep = (delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs));
const withTimeout = (promise, delayMs) =>
  Promise.race([
    promise,
    sleep(delayMs).then(() => undefined)
  ]);
const smokeLoadCount = Number(sessionStorage.getItem('blanche-smoke-load-count') ?? '0') + 1;
sessionStorage.setItem('blanche-smoke-load-count', String(smokeLoadCount));
window.__BLANCHE_SMOKE_LOAD_COUNT__ = smokeLoadCount;
const openDatabase = () =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open('blanche-smoke-db', 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('records')) {
        db.createObjectStore('records', { keyPath: 'id' });
      }
    };
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('records', 'readwrite');
      tx.objectStore('records').put({ id: 'first', value: 'from-indexeddb' });
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    };
  });

localStorage.setItem('blanche-smoke-local', 'local-value');
sessionStorage.setItem('blanche-smoke-session', 'session-value');
const dynamicSearchInput = document.querySelector('#site-dynamic-search-input');
document.querySelector('#site-dynamic-search-submit')?.addEventListener('click', () => {
  const query = dynamicSearchInput?.value?.trim() ?? '';
  location.assign('/search/dynamic?q=' + encodeURIComponent(query) + '&view=widget');
});
if (localStorage.getItem('blanche-feature-flags') === null) {
  localStorage.setItem('blanche-feature-flags', JSON.stringify({
    compactDashboard: false,
    hiddenTelemetryPanel: false
  }));
}
const localFeatureFlags = JSON.parse(
  localStorage.getItem('blanche-feature-flags') ?? '{}'
);
if (localFeatureFlags.compactDashboard === true) {
  const compactDashboard = document.createElement('section');
  compactDashboard.id = 'compact-dashboard-panel';
  compactDashboard.dataset.feature = 'compactDashboard';
  compactDashboard.setAttribute('aria-label', 'Compact dashboard preview');
  compactDashboard.textContent = 'Compact dashboard feature is enabled.';
  document.body.append(compactDashboard);
}

const shippedFeatureDefaults = {
  smokeWebpackFeature: false,
  legacyNavigationEnabled: true
};
const isEnabled = (key) => Boolean(shippedFeatureDefaults[key]);
window.__BLANCHE_SMOKE_FEATURE_USED__ = isEnabled('smokeWebpackFeature');
const deliveredFeatureConfig = await fetch('/feature-config.json').then((response) => response.json());
window.__FEATURE_FLAGS__ = deliveredFeatureConfig.features;
window.__CONFIG__ = deliveredFeatureConfig;

const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8" fill="#0aa"/></svg>';
const blobUrl = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
const blobImage = document.createElement('img');
blobImage.id = 'blob-image';
blobImage.src = blobUrl;
document.body.append(blobImage);

const dataImage = document.createElement('img');
dataImage.id = 'data-image';
dataImage.src = 'data:image/gif;base64,R0lGODlhAQABAAAAACw=';
document.body.append(dataImage);

const worker = new Worker('/worker.js', { name: 'blanche-smoke-worker' });
worker.postMessage('ping');

try {
  await openDatabase();

  if ('caches' in window) {
    const cache = await caches.open('blanche-smoke-cache');
    await cache.put('/cached.txt', new Response('cached body', {
      headers: { 'content-type': 'text/plain' }
    }));
  }

  if ('serviceWorker' in navigator) {
    const registration = await navigator.serviceWorker.register('/sw.js');
    await withTimeout(navigator.serviceWorker.ready, 1500);
    await withTimeout(registration.update(), 1500);
  }
} catch (error) {
  window.__blancheSmokeSetupError = error instanceof Error ? error.message : String(error);
} finally {
  window.__blancheSmokeReady = true;
  document.body.dataset.blancheSmokeReady = 'true';
}
`;
}

function createIngestServer() {
  return http.createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', `http://${request.headers.host}`);
    if (request.method === 'OPTIONS') {
      ingestOptionsCount += 1;
      sendJson(response, 204, undefined);
      return;
    }

    if (request.method !== 'POST' || ![LOOPBACK_PATH, LOOPBACK_OSINT_SEED_PATH].includes(url.pathname)) {
      sendJson(response, 404, {
        status: 'error',
        message: 'Unknown smoke ingest route.'
      });
      return;
    }

    const rawBody = await readRequestBody(request);
    ingestContentTypes.push(String(request.headers['content-type'] ?? ''));
    if (url.pathname === LOOPBACK_OSINT_SEED_PATH) {
      latestIngestedSeed = JSON.parse(rawBody);
      sendJson(response, 202, {
        status: 'accepted',
        primaryHostname: latestIngestedSeed?.seed?.primaryHostname ?? '',
        relatedHostCount: latestIngestedSeed?.browserContext?.relatedHosts?.length ?? 0
      });
      return;
    }

    const receivedExport = JSON.parse(rawBody);
    if (!latestIngestedExport || receivedExport?.collection?.mode === 'instrumented') {
      latestIngestedExport = receivedExport;
    }
    const chromiumOnlyCounts = countChromiumOnlyArtifacts(receivedExport?.artifacts ?? []);
    sendJson(response, 200, {
      status: 'ok',
      artifactCount: receivedExport?.summary?.artifactCount ?? 0,
      chromiumOnlyArtifactCount: Object.values(chromiumOnlyCounts).reduce((sum, count) => sum + count, 0)
    });
  });
}

function sendText(response, statusCode, contentType, body, headers = {}) {
  response.writeHead(statusCode, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(body),
    ...headers
  });
  response.end(body);
}

function sendJson(response, statusCode, payload) {
  const body = payload === undefined ? '' : JSON.stringify(payload);
  response.writeHead(statusCode, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  response.end(body);
}

async function readRequestBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

function listen(server, host, port) {
  return new Promise((resolve, reject) => {
    const handleError = (error) => {
      server.off('listening', handleListening);
      reject(error);
    };
    const handleListening = () => {
      server.off('error', handleError);
      resolve(server.address().port);
    };
    server.once('error', handleError);
    server.once('listening', handleListening);
    server.listen(port, host);
  });
}

async function listenPreferred(server, host, preferredPort) {
  try {
    return await listen(server, host, preferredPort);
  } catch (error) {
    if (error?.code !== 'EADDRINUSE') {
      throw error;
    }

    return await listen(server, host, 0);
  }
}

function getFreePort() {
  const server = http.createServer();
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, LOOPBACK_HOST, () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function launchChrome(executable, { debugPort, extensionDir, userDataDir, testUrl }) {
  const args = [
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${userDataDir}`,
    `--disable-extensions-except=${extensionDir}`,
    `--load-extension=${extensionDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-popup-blocking',
    '--disable-background-networking',
    testUrl
  ];
  const child = childProcess.spawn(executable, args, {
    stdio: ['ignore', 'ignore', 'pipe']
  });

  let stderr = '';
  child.stderr?.on('data', (chunk) => {
    stderr += chunk.toString();
  });
  child.once('exit', (code) => {
    if (code && !latestIngestedExport) {
      console.error(stderr.trim());
    }
  });

  return child;
}

async function stopChrome(child, userDataDir) {
  if (!child) {
    return;
  }

  if (process.platform === 'win32') {
    await stopWindowsProcessesForProfile(userDataDir);
    await stopWindowsProcessesForProfile(userDataDir);
  }

  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }

  await new Promise((resolve) => {
    const timeout = setTimeout(resolve, 3000);
    child.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
    }
  });
}

async function stopWindowsProcessesForProfile(userDataDir) {
  if (process.platform !== 'win32') {
    return;
  }

  await execFileQuiet(
    'powershell',
    [
      '-NoProfile',
      '-Command',
      [
        '$targetProfile = $env:BLANCHE_PROFILE_TO_KILL;',
        'if (-not $targetProfile) { exit 0 };',
        '$pids = @(Get-CimInstance Win32_Process |',
        'Where-Object { $_.CommandLine -and $_.CommandLine.Contains($targetProfile) } |',
        'Select-Object -ExpandProperty ProcessId);',
        'foreach ($procId in $pids) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }'
      ].join(' ')
    ],
    {
      env: {
        ...process.env,
        BLANCHE_PROFILE_TO_KILL: userDataDir
      }
    }
  );

  await new Promise((resolve) => setTimeout(resolve, 500));
}

function execFileQuiet(file, args, options = {}) {
  return new Promise((resolve) => {
    childProcess.execFile(
      file,
      args,
      {
        timeout: 10000,
        windowsHide: true,
        ...options
      },
      () => resolve()
    );
  });
}

async function removeDirectoryWithRetry(directory) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      await fs.rm(directory, { recursive: true, force: true });
      return;
    } catch (error) {
      if (!['EBUSY', 'ENOTEMPTY', 'EPERM'].includes(error?.code)) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  if (process.env.BLANCHE_SMOKE_DEBUG) {
    console.warn(`Unable to remove temporary Chrome profile after retries: ${directory}`);
  }
}

async function connectToBrowser(debugPort) {
  const version = await waitFor(
    async () => {
      try {
        return await fetchJson(`http://${LOOPBACK_HOST}:${debugPort}/json/version`);
      } catch {
        return undefined;
      }
    },
    15000,
    100,
    'Chrome remote debugging endpoint'
  );
  return CdpClient.connect(version.webSocketDebuggerUrl);
}

async function connectToTarget(debugPort, targetId) {
  const target = await waitFor(
    async () => {
      const targets = await fetchJson(`http://${LOOPBACK_HOST}:${debugPort}/json/list`);
      return targets.find((candidate) => candidate.id === targetId && candidate.webSocketDebuggerUrl);
    },
    10000,
    100,
    `CDP target ${targetId}`
  );
  return CdpClient.connect(target.webSocketDebuggerUrl);
}

async function findExtensionId(browserClient, debugPort, userDataDir) {
  return await waitFor(
    async () => {
      const targetResult = await browserClient.send('Target.getTargets');
      const extensionTarget = targetResult.targetInfos.find(
        (target) =>
          target.url?.startsWith('chrome-extension://') &&
          (target.url.endsWith('/dist/background.js') || target.url.endsWith('/background.js'))
      );
      const fromTarget = extensionTarget ? extensionTarget.url.split('/')[2] : undefined;
      if (fromTarget) {
        return fromTarget;
      }

      const fromPreferences = await findExtensionIdFromPreferences(userDataDir);
      if (fromPreferences) {
        return fromPreferences;
      }

      const listedTargets = await fetchJson(`http://${LOOPBACK_HOST}:${debugPort}/json/list`);
      const listedExtension = listedTargets.find(
        (target) =>
          target.url?.startsWith('chrome-extension://') &&
          target.url.includes('/dist/background.js')
      );
      return listedExtension ? listedExtension.url.split('/')[2] : undefined;
    },
    15000,
    100,
    'the BLANCHE extension id'
  );
}

async function findExtensionIdFromPreferences(userDataDir) {
  try {
    const preferencesPath = path.join(userDataDir, 'Default', 'Preferences');
    const preferences = JSON.parse(await fs.readFile(preferencesPath, 'utf8'));
    const settings = preferences?.extensions?.settings ?? {};
    for (const [extensionId, value] of Object.entries(settings)) {
      if (value?.manifest?.name === 'BLANCHE') {
        return extensionId;
      }
      if (typeof value?.path === 'string' && path.normalize(value.path) === path.normalize(extensionDir)) {
        return extensionId;
      }
    }
  } catch {
    return undefined;
  }

  return undefined;
}

function buildRunActionExpression({
  testOrigin,
  reviewScopeOrigin,
  ingestUrl,
  osintSeedUrl,
  tearSheetOnly = false,
  targetUrlControlsOnly = false,
  siteSearchOnly = false
}) {
  return `(${async function runExtensionWorkflows(input) {
    const sleep = (delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs));
    const assert = (condition, message) => {
      if (!condition) {
        throw new Error(`Workflow verification failed: ${message}`);
      }
    };
    const assertAssessmentEvidence = (assessment, label) => {
      const evidenceIds = new Set(
        (assessment?.evidence ?? []).map((entry) => entry.evidenceId).filter(Boolean)
      );
      assert(evidenceIds.size > 0, `${label} retains bounded evidence records.`);
      const evidenceRefs = [
        ...(assessment?.transform?.signals ?? []).flatMap((signal) => signal.evidenceRefs ?? []),
        ...(assessment?.purposeClaims ?? []).flatMap((claim) => claim.evidenceRefs ?? []),
        ...(assessment?.behaviorClaims ?? []).flatMap((claim) => claim.evidenceRefs ?? []),
        ...(assessment?.indicators ?? []).flatMap((indicator) => indicator.evidenceRefs ?? []),
        ...(assessment?.reviewPriority?.factors ?? []).flatMap(
          (factor) => factor.evidenceRefs ?? []
        )
      ];
      assert(
        evidenceRefs.every((reference) => evidenceIds.has(reference)),
        `${label} claim, indicator, transform, and priority references resolve to retained evidence.`
      );
    };
    const waitFor = async (callback, timeoutMs, intervalMs, label) => {
      const startedAt = Date.now();
      let lastError;
      while (Date.now() - startedAt < timeoutMs) {
        try {
          const value = await callback();
          if (value) {
            return value;
          }
        } catch (error) {
          lastError = error;
        }
        await sleep(intervalMs);
      }

      throw new Error(
        `Timed out waiting for ${label}${lastError ? `: ${lastError.message ?? String(lastError)}` : ''}`
      );
    };
    const sendBlancheMessage = async (message) => {
      let lastError;
      for (let attempt = 0; attempt < 50; attempt += 1) {
        try {
          const response = await chrome.runtime.sendMessage(message);
          if (response) {
            return response;
          }
          lastError = new Error('BLANCHE background returned no response.');
        } catch (error) {
          lastError = error;
        }
        await sleep(100);
      }

      throw lastError ?? new Error('BLANCHE background did not respond.');
    };
    const getState = async () => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/getState',
        payload: {
          includeLogs: true
        }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? 'Unable to read extension state.');
      }
      return response.payload;
    };
    const queryTraffic = async (query) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'traffic/query',
        payload: query
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? 'Unable to query the traffic ledger.');
      }
      return response.payload;
    };
    const updateModuleSettings = async (moduleId, settings) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/updateModuleSettings',
        payload: {
          moduleId,
          settings
        }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? `Unable to update settings for ${moduleId}.`);
      }
      return response.payload;
    };
    const updateEngagementProfiles = async (engagementProfiles) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/updateEngagementProfiles',
        payload: { engagementProfiles }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? 'Unable to update engagement profiles.');
      }
      return response.payload;
    };
    const activateEngagementProfile = async (profileId) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/activateEngagementProfile',
        payload: { profileId }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? `Unable to activate engagement profile ${profileId}.`);
      }
      return response.payload;
    };
    const toggleModule = async (moduleId, enabled) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/toggleModule',
        payload: {
          moduleId,
          enabled
        }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? `Unable to toggle ${moduleId}.`);
      }
      return response.payload;
    };
    const updateSearchWorkbench = async (searchWorkbench) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/updateSearchWorkbench',
        payload: {
          searchWorkbench
        }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? 'Unable to update search workbench.');
      }
      return response.payload;
    };
    const updateInterestWorkbench = async (interestWorkbench) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/updateInterestWorkbench',
        payload: {
          interestWorkbench
        }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? 'Unable to update interest workbench.');
      }
      return response.payload;
    };
    const runInterestAction = async (action, tabId) => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/runInterestAction',
        payload: {
          action,
          tabId
        }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? `Interest action failed: ${action}`);
      }
      return response.payload;
    };
    const runAction = async (moduleId, actionId, tabId, actionInput, caller = 'sidepanel') => {
      const response = await sendBlancheMessage({
        channel: 'blanche',
        type: 'core/runAction',
        payload: {
          moduleId,
          actionId,
          tabId,
          caller,
          input: actionInput
        }
      });
      if (!response?.ok) {
        throw new Error(response?.error ?? `${moduleId}/${actionId} action failed.`);
      }
      return response.payload;
    };
    const dispatchInput = (element, value) => {
      element.value = value;
      element.dispatchEvent(new Event('input', { bubbles: true }));
      element.dispatchEvent(new Event('change', { bubbles: true }));
    };
    const clickButton = (selector) => {
      const button = document.querySelector(selector);
      assert(button, `Button not found: ${selector}`);
      assert(!button.disabled, `Button is disabled: ${selector}`);
      button.click();
    };
    const waitForSelectedNerdSurface = async (surfaceId, label) => {
      await waitFor(async () => {
        const executionState = await getState();
        const selectedCard = document.querySelector(
          `[data-nerd-surface="${surfaceId}"].is-selected`
        );
        const launchButton = document.querySelector('[data-search-action="launch-nerd"]');
        return executionState.searchWorkbench.selectedNerdSurfaceId === surfaceId &&
          selectedCard?.isConnected &&
          launchButton?.isConnected &&
          !launchButton.disabled;
      }, 10000, 100, `${label} to finish rendering as the selected NERD surface`);
    };
    const selectSavedNerdSurface = async (surfaceId, label) => {
      await waitFor(async () => {
        const executionState = await getState();
        const selectedCard = document.querySelector(
          `[data-nerd-surface="${surfaceId}"].is-selected`
        );
        const launchButton = document.querySelector('[data-search-action="launch-nerd"]');
        if (
          executionState.searchWorkbench.selectedNerdSurfaceId === surfaceId &&
          selectedCard?.isConnected &&
          launchButton?.isConnected &&
          !launchButton.disabled
        ) {
          return true;
        }
        const button = document.querySelector(`[data-nerd-select="${surfaceId}"]`);
        if (!button?.isConnected || button.disabled) return false;
        button.click();
        return true;
      }, 10000, 100, `${label} selection control to become ready`);
      await waitForSelectedNerdSurface(surfaceId, label);
    };
    const refreshConsole = async () => {
      clickButton('[data-action="refresh"]');
      await waitFor(
        () => document.querySelector('[data-action="refresh"]')?.disabled === false,
        10000,
        100,
        'the BLANCHE console refresh to complete'
      );
    };
    const openDisclosureThroughPoll = async (selector, label) => {
      const original = await waitFor(
        () => document.querySelector(selector),
        10000,
        100,
        `${label} disclosure to render`
      );
      assert(original instanceof HTMLDetailsElement, `${label} uses a native details element.`);
      assert(original.dataset.disclosureKey, `${label} has a stable disclosure key.`);
      if (!original.open) {
        const summary = original.querySelector('summary');
        assert(summary, `${label} has a clickable summary.`);
        summary.focus();
        summary.click();
      }
      await waitFor(() => original.open, 2000, 50, `${label} disclosure to open`);
      await waitFor(
        () => !original.isConnected,
        6000,
        50,
        `${label} disclosure to be replaced by a successful state poll`
      );
      const current = document.querySelector(selector);
      assert(
        current instanceof HTMLDetailsElement && current.open,
        `${label} remains open on the live DOM after polling.`
      );
      assert(
        document.activeElement === current.querySelector('summary'),
        `${label} keeps keyboard focus on its live summary after polling.`
      );
      return current;
    };
    const closeTabs = async (tabs) => {
      const ids = tabs.map((tab) => tab.id).filter((id) => typeof id === 'number');
      if (ids.length) {
        await chrome.tabs.remove(ids);
      }
    };
    const waitForTargetReady = async (tabId) => {
      await waitFor(async () => {
        const [result] = await chrome.scripting.executeScript({
          target: {
            tabId
          },
          func: () => document.body?.dataset?.blancheSmokeReady === 'true'
        });
        return result?.result === true;
      }, 20000, 250, 'the smoke target page to finish setup');
    };
    const executeInTarget = async (tabId, func, args = [], stage = 'unnamed stage') => {
      let lastError;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const [result] = await chrome.scripting.executeScript({
            target: {
              tabId
            },
            func,
            args
          });
          return result?.result;
        } catch (error) {
          lastError = error;
          const message = error instanceof Error ? error.message : String(error);
          if (attempt < 2 && /Frame with ID 0 was removed/i.test(message)) {
            await sleep(250);
            await waitForTargetReady(tabId);
            continue;
          }
          break;
        }
      }
      const tab = await chrome.tabs.get(tabId).catch(() => undefined);
      throw new Error(
        `Target script failed during ${stage} (${tab?.url ?? `tab ${tabId}`}): ${
          lastError instanceof Error ? lastError.message : String(lastError)
        }`
      );
    };
    const exerciseTearSheetReport = async (bridgePassive, { download = false } = {}) => {
      await refreshConsole();
      await waitFor(
        () => document.querySelector('[data-primary-view="report"]'),
        10000,
        100,
        'the Report navigation item to render'
      );
      clickButton('[data-primary-view="report"]');
      await waitFor(
        () =>
          document.querySelector('[data-tear-sheet-report]') &&
          document.querySelector('[data-report-mode="stakeholder"]') &&
          document.querySelector('[data-report-mode="json"]'),
        10000,
        100,
        'the tear sheet report controls to render'
      );

      clickButton('[data-report-mode="stakeholder"]');
      const stakeholderReportRoot = await waitFor(
        () => {
          const root = document.querySelector('[data-tear-sheet-report]');
          return root?.textContent?.trim() ? root : undefined;
        },
        10000,
        100,
        'the stakeholder tear sheet report to render'
      );
      const expectedReportHostname = new URL(input.testOrigin).hostname;
      const stakeholderReportText =
        stakeholderReportRoot.closest('.report-preview')?.textContent ?? stakeholderReportRoot.textContent ?? '';
      assert(
        stakeholderReportText.includes(expectedReportHostname),
        'Stakeholder report includes the captured target hostname.'
      );
      assert(/limitations/i.test(stakeholderReportText), 'Stakeholder report renders limitations.');
      assert(/provenance/i.test(stakeholderReportText), 'Stakeholder report renders provenance.');
      if (!input.tearSheetOnly) {
        assert(
          /Dork suite/i.test(stakeholderReportText) &&
            /NERD mode/i.test(stakeholderReportText) &&
            /Exact query/i.test(stakeholderReportText),
          'Stakeholder report renders Dork Suite and NERD exact-query outputs.'
        );
      }
      assert(
        !stakeholderReportText.includes('local-value') && !stakeholderReportText.includes('session-value'),
        'Stakeholder report masks raw browser-storage values.'
      );

      const sensitiveNoticeText = document.querySelector('.report-sensitive-note')?.textContent ?? '';
      assert(/assessment-sensitive/i.test(sensitiveNoticeText), 'Report renders its sensitive-data notice.');
      const reportControls = {
        root: Boolean(document.querySelector('[data-tear-sheet-report]')),
        stakeholderMode: Boolean(document.querySelector('[data-report-mode="stakeholder"]')),
        jsonMode: Boolean(document.querySelector('[data-report-mode="json"]')),
        htmlDownload: Boolean(document.querySelector('[data-report-download="html"]')),
        jsonDownload: Boolean(document.querySelector('[data-report-download="json"]'))
      };
      assert(reportControls.root, 'Report root is present.');
      assert(reportControls.stakeholderMode, 'Stakeholder report mode is present.');
      assert(reportControls.jsonMode, 'JSON report mode is present.');
      assert(reportControls.htmlDownload, 'HTML report download is present.');
      assert(reportControls.jsonDownload, 'JSON report download is present.');

      const downloadClicks = { html: false, json: false };
      if (download) {
        clickButton('[data-report-download="html"]');
        downloadClicks.html = true;
        await sleep(100);
        clickButton('[data-report-download="json"]');
        downloadClicks.json = true;
        await sleep(100);
      }

      clickButton('[data-report-mode="json"]');
      const reportJsonText = await waitFor(
        () => {
          const field = document.querySelector('[data-report-json]');
          const value = field?.value ?? field?.textContent ?? '';
          return value.trim().startsWith('{') ? value : undefined;
        },
        10000,
        100,
        'the full tear sheet JSON to render'
      );
      const reportCopyPresent = Boolean(document.querySelector('[data-report-copy]'));
      assert(reportCopyPresent, 'Report copy control is present.');

      const tearSheetReport = JSON.parse(reportJsonText);
      const sourceCapture = bridgePassive.export;
      const embeddedSourceCapture = tearSheetReport.sourceCapture;
      const provenance = tearSheetReport.evidenceSummary?.provenance;
      assert(tearSheetReport.kind === 'blanche.tear-sheet', 'Report JSON uses the tear sheet kind.');
      assert(tearSheetReport.schemaVersion === '1.0.0', 'Report JSON uses the supported schema version.');
      assert(
        embeddedSourceCapture?.exportMetadata?.exportId === sourceCapture?.exportMetadata?.exportId &&
          tearSheetReport.metadata?.sourceExportId === embeddedSourceCapture?.exportMetadata?.exportId,
        'Report JSON embeds and references the passive source export ID.'
      );
      assert(
        embeddedSourceCapture?.summary?.artifactCount === sourceCapture?.summary?.artifactCount &&
          tearSheetReport.evidenceSummary?.artifactCount === embeddedSourceCapture?.summary?.artifactCount,
        'Report JSON embeds and summarizes the passive source artifact count.'
      );
      assert(
        tearSheetReport.target?.hostname === expectedReportHostname,
        'Report JSON preserves the captured target hostname.'
      );
      assert(
        Array.isArray(tearSheetReport.limitations) && tearSheetReport.limitations.length > 0,
        'Report JSON includes capture limitations.'
      );
      assert(
        provenance &&
          Number.isInteger(provenance.observed) &&
          Number.isInteger(provenance.inferred) &&
          Number.isInteger(provenance.unavailable),
        'Report JSON includes provenance totals.'
      );
      assert(
        provenance.observed + provenance.inferred + provenance.unavailable ===
          tearSheetReport.evidenceSummary.artifactCount,
        'Report provenance totals account for every captured artifact.'
      );
      assert(
        Array.isArray(tearSheetReport.evidenceSummary.categories) &&
          tearSheetReport.evidenceSummary.categories.every((category) => {
            const categoryProvenance = category.provenance;
            return categoryProvenance &&
              Number.isInteger(categoryProvenance.observed) &&
              Number.isInteger(categoryProvenance.inferred) &&
              Number.isInteger(categoryProvenance.unavailable);
          }),
        'Report JSON includes provenance totals for every evidence category.'
      );

      const browserOnlyCategories = new Set([
        'blob',
        'data-url',
        'storage-key',
        'indexeddb-database',
        'cache',
        'service-worker',
        'runtime-indicator'
      ]);
      const browserOnlyArtifactCount = embeddedSourceCapture.artifacts.filter((artifact) =>
        browserOnlyCategories.has(artifact.category) ||
        artifact.kind?.startsWith('instrumented-') ||
        /^(blob|data):/i.test(artifact.url ?? '') ||
        artifact.discoveredBy?.includes('instrumentation')
      ).length;
      assert(browserOnlyArtifactCount > 0, 'Passive capture contains browser-only evidence.');
      assert(
        tearSheetReport.evidenceSummary.browserOnlyArtifactCount === browserOnlyArtifactCount,
        'Report browser-only count matches the report predicate over source artifacts.'
      );
      assert(
        tearSheetReport.dataHandling?.classification === 'assessment-sensitive' &&
          tearSheetReport.dataHandling?.stakeholderViewRedactsRawValues === true &&
          tearSheetReport.dataHandling?.jsonContainsFullEvidence === true,
        'Report declares stakeholder masking and full-fidelity JSON handling.'
      );
      assert(
        reportJsonText.includes('local-value') && reportJsonText.includes('session-value'),
        'JSON evidence preserves raw browser-storage values hidden from stakeholders.'
      );
      if (!input.tearSheetOnly) {
        const reportedSearchSessions = tearSheetReport.correlatedEvidence?.searchSessions ?? [];
        const reportedDorkSuite = reportedSearchSessions.find(
          (session) => session.mode === 'dork-suite'
        );
        const reportedNerdSuites = reportedSearchSessions.filter(
          (session) => session.mode === 'nerd'
        );
        const reportedDorkTasks = reportedDorkSuite?.tasks ?? [];
        assert(
          [
            ['google', 'after'],
            ['bing', 'prefer'],
            ['duckduckgo', 'ddg-semantic']
          ].every(([dialect, advancedOperatorId]) =>
            reportedDorkTasks.some(
              (task) =>
                task.dorkId &&
                task.dialect === dialect &&
                task.operatorIds?.includes('site') &&
                task.operatorIds?.includes(advancedOperatorId) &&
                task.query?.includes('site:127.0.0.1')
            )
          ),
          'Report JSON contains traditional and advanced Google, Bing, and DuckDuckGo Dork Suite traces.'
        );
        assert(
          reportedNerdSuites.some((session) =>
            session.tasks?.some(
              (task) =>
                task.nerdSurface?.mode === 'get' &&
                task.status === 'completed-results' &&
                task.results?.some((result) => result.url?.includes('/docs/readme.txt'))
            )
          ),
          'Report JSON contains the completed GET NERD surface and parsed result output.'
        );
        assert(
          reportedNerdSuites.some((session) =>
            session.tasks?.some(
              (task) =>
                task.nerdSurface?.mode === 'form' &&
                task.nerdSurface?.method === 'post' &&
                task.status === 'completed-results' &&
                !JSON.stringify(task).includes('must-not-be-reported') &&
                task.results?.some((result) => result.url?.includes('from=nerd-post'))
            )
          ),
          'Report JSON contains the sanitized POST NERD trace and parsed result output.'
        );
        assert(
          reportedNerdSuites.some((session) =>
            session.tasks?.some(
              (task) =>
                task.nerdSurface?.mode === 'form' &&
                task.nerdSurface?.method === 'dynamic' &&
                task.status === 'completed-results' &&
                !JSON.stringify(task).includes('must-not-be-reported') &&
                task.results?.some((result) => result.url?.includes('from=nerd-dynamic'))
            )
          ),
          'Report JSON contains the sanitized JavaScript-driven NERD trace and parsed result output.'
        );
        assert(
          reportedNerdSuites.some((session) =>
            session.tasks?.some(
              (task) =>
                task.nerdSurface?.mode === 'template' &&
                task.status === 'completed-results' &&
                task.searchUrl?.includes('section=template')
            )
          ),
          'Report JSON contains the completed reviewed-template NERD trace.'
        );
      }

      return {
        payload: tearSheetReport,
        controls: {
          ...reportControls,
          copy: reportCopyPresent,
          jsonTextarea: Boolean(document.querySelector('[data-report-json]'))
        },
        downloadsRequested: downloadClicks,
        masking: {
          sensitiveNotice: /assessment-sensitive/i.test(sensitiveNoticeText),
          stakeholderStorageValuesHidden: true,
          jsonStorageValuesRetained: true
        }
      };
    };

    const tabs = await chrome.tabs.query({ url: `${input.testOrigin}/*` });
    const targetTab = tabs.find((tab) => tab.url && tab.url.startsWith(`${input.testOrigin}/`));
    if (!targetTab?.id) {
      throw new Error(`Unable to find smoke target tab for ${input.testOrigin}`);
    }
    await chrome.tabs.update(targetTab.id, { active: true });
    await waitForTargetReady(targetTab.id);

    if (input.tearSheetOnly) {
      await waitFor(
        () =>
          document.querySelector('[data-action="refresh"]') &&
          document.querySelector('[data-primary-view="report"]'),
        15000,
        100,
        'the BLANCHE report console to render'
      );
      await updateModuleSettings('burp-bridge', {
        defaultMode: 'passive',
        reloadBeforeCollect: false,
        autoSendToBurp: false,
        burpIngestUrl: input.ingestUrl,
        resourceEntryLimit: 500,
        cacheEntryLimit: 100,
        storageValueLimit: 800
      });
      const bridgePassive = await runAction('burp-bridge', 'collectPassive', targetTab.id);
      assert(bridgePassive.export?.collection?.mode === 'passive', 'Burp Bridge passive action used passive mode.');
      assert(
        bridgePassive.warnings?.some((warning) => warning.code === 'PASSIVE_MODE_PROVENANCE_LIMIT'),
        'Passive collection surfaces provenance warnings.'
      );
      const report = await exerciseTearSheetReport(bridgePassive, { download: true });
      return {
        mode: 'tear-sheet-only',
        bridgePassive,
        report
      };
    }

    await waitFor(
      () =>
        document.querySelector('[data-home-action="run-search"]') &&
        document.querySelector('[data-primary-view="search"]'),
      15000,
      100,
      'the BLANCHE operator console to render'
    );

    const targetControlQuery =
      'duplicate=one&duplicate=two&blank=&bare&plus=one+two&encoded=%E2%9C%93';
    const targetControlFragment = 'smoke-fragment';
    const targetControlUrl = await executeInTarget(
      targetTab.id,
      ({ query, fragment }) => {
        history.replaceState(
          { blancheTargetControlSmoke: true },
          '',
          `/?${query}#${fragment}`
        );
        return location.href;
      },
      [{ query: targetControlQuery, fragment: targetControlFragment }],
      'target URL control fixture setup'
    );
    await waitFor(
      async () => (await chrome.tabs.get(targetTab.id)).url === targetControlUrl,
      10000,
      100,
      'the target tab URL to include the control fixture parameters'
    );
    await refreshConsole();

    const targetUrlDisclosure = await waitFor(
      () => document.querySelector('.target-url-disclosure'),
      10000,
      100,
      'the target URL disclosure to render'
    );
    assert(
      targetUrlDisclosure instanceof HTMLDetailsElement,
      'Target URL disclosure uses a native details element.'
    );
    assert(targetUrlDisclosure.open === false, 'Target URL disclosure starts closed.');
    assert(
      !targetUrlDisclosure.innerText.includes(targetControlUrl),
      'Collapsed target URL disclosure does not consume space with the full URL.'
    );
    const targetUrlSummary = targetUrlDisclosure.querySelector('summary');
    assert(targetUrlSummary, 'Target URL disclosure has a clickable summary.');
    assert(
      targetUrlSummary.getAttribute('aria-label') === 'Full target URL',
      'Target URL disclosure has a state-neutral accessible name.'
    );
    targetUrlSummary.focus();
    targetUrlSummary.click();
    await waitFor(
      () =>
        targetUrlDisclosure.open === true &&
        targetUrlDisclosure.innerText.includes(targetControlUrl),
      10000,
      50,
      'the full target URL to become visible'
    );

    let pollPersistenceVerified = false;
    let refreshPersistenceVerified = false;
    let closePersistenceVerified = false;
    const disclosureFamiliesVerified = [];
    if (input.targetUrlControlsOnly) {
      await waitFor(
        () => !targetUrlDisclosure.isConnected,
        6000,
        50,
        'the initially opened target URL disclosure to be replaced by polling'
      );
      let liveTargetDisclosure = document.querySelector('.target-url-disclosure');
      assert(
        liveTargetDisclosure instanceof HTMLDetailsElement &&
          liveTargetDisclosure.open &&
          liveTargetDisclosure.innerText.includes(targetControlUrl),
        'The live target URL disclosure remains open with the exact URL after polling.'
      );
      assert(
        document.activeElement === liveTargetDisclosure.querySelector('summary'),
        'The live target URL summary retains keyboard focus after polling.'
      );
      pollPersistenceVerified = true;
      const preRefreshDisclosure = liveTargetDisclosure;
      await refreshConsole();
      await waitFor(
        () => !preRefreshDisclosure.isConnected,
        3000,
        50,
        'the target URL disclosure to be replaced by explicit refresh'
      );
      liveTargetDisclosure = document.querySelector('.target-url-disclosure');
      assert(
        liveTargetDisclosure instanceof HTMLDetailsElement && liveTargetDisclosure.open,
        'The target URL disclosure remains open after explicit refresh.'
      );
      refreshPersistenceVerified = true;
      disclosureFamiliesVerified.push('target-url');
    }

    const clipboardWrites = [];
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (value) => {
          clipboardWrites.push(String(value));
        }
      }
    });
    const parsedTargetControlUrl = new URL(targetControlUrl);
    const targetControlPath = parsedTargetControlUrl.pathname || '/';
    const targetControlParameters = parsedTargetControlUrl.search.slice(1);
    const expectedTargetCopies = {
      url: targetControlUrl,
      params: targetControlParameters,
      get: [
        `GET ${targetControlPath}${parsedTargetControlUrl.search} HTTP/1.1`,
        `Host: ${parsedTargetControlUrl.host}`,
        '',
        ''
      ].join('\r\n'),
      post: [
        `POST ${targetControlPath} HTTP/1.1`,
        `Host: ${parsedTargetControlUrl.host}`,
        'Content-Type: application/x-www-form-urlencoded',
        `Content-Length: ${new TextEncoder().encode(targetControlParameters).byteLength}`,
        '',
        targetControlParameters
      ].join('\r\n')
    };
    const expectedTargetCopyNotices = {
      url: 'Copied the full target URL.',
      params: 'Copied the target URL parameters.',
      get: 'Copied a Burp-compatible GET request template.',
      post: 'Copied a constructed form POST request template from the target URL parameters.'
    };
    const targetCopyActions = ['url', 'params', 'get', 'post'];
    const targetOutputSelects = [...document.querySelectorAll('[data-target-output-select]')];
    assert(
      targetOutputSelects.length === 1 &&
        targetOutputSelects[0] instanceof HTMLSelectElement,
      'Target output exposes one URL/output tool selector.'
    );
    const targetOutputSelect = targetOutputSelects[0];
    assert(
      JSON.stringify([...targetOutputSelect.options].map((option) => option.value)) ===
        JSON.stringify(targetCopyActions),
      'Target output selector exposes URL, parameters, GET, and POST in order.'
    );
    for (const action of targetCopyActions) {
      targetOutputSelect.value = action;
      targetOutputSelect.dispatchEvent(new Event('change', { bubbles: true }));
      await waitFor(
        () =>
          targetOutputSelect.value === action &&
          document.querySelector(
            '.target-output-preview [data-target-output-value]'
          )?.textContent === expectedTargetCopies[action],
        10000,
        50,
        `the ${action} target output preview to show the exact payload`
      );
    }
    const targetNoticeLine = document.querySelector('.notice-line');
    assert(
      targetNoticeLine?.getAttribute('role') === 'status' &&
        targetNoticeLine?.getAttribute('aria-live') === 'polite',
      'Target copy confirmations use a polite live status region.'
    );
    for (const action of targetCopyActions) {
      const writeCountBefore = clipboardWrites.length;
      const targetCopyButton = document.querySelector(`[data-target-copy="${action}"]`);
      assert(targetCopyButton instanceof HTMLButtonElement, `${action} target copy button is available.`);
      targetCopyButton.focus();
      targetCopyButton.click();
      await waitFor(
        () => clipboardWrites.length === writeCountBefore + 1,
        10000,
        50,
        `the ${action} target control to write to the clipboard`
      );
      assert(
        clipboardWrites.at(-1) === expectedTargetCopies[action],
        `${action} target control copies the exact expected payload.`
      );
      await waitFor(
        () =>
          document.querySelector('.notice-line')?.textContent?.trim() ===
          expectedTargetCopyNotices[action],
        10000,
        50,
        `the ${action} target copy notice to render`
      );
      assert(
        document.activeElement?.getAttribute('data-target-copy') === action,
        `${action} target copy control retains keyboard focus after its confirmation.`
      );
    }
    assert(
      targetControlParameters === targetControlQuery &&
        parsedTargetControlUrl.searchParams.getAll('duplicate').length === 2 &&
        parsedTargetControlUrl.searchParams.has('bare') &&
        parsedTargetControlUrl.searchParams.get('blank') === '' &&
        parsedTargetControlUrl.searchParams.get('plus') === 'one two' &&
        parsedTargetControlUrl.searchParams.get('encoded') === '✓',
      'Target URL control fixture retains duplicate, blank, bare, plus, and encoded parameters.'
    );
    const targetOutputStage = document.querySelector('.target-output-stage');
    const runSearchAction = document.querySelector('[data-home-action="run-search"]');
    const resultsStage = document.querySelector('.stage-results');
    assert(
      targetOutputStage &&
        runSearchAction &&
        resultsStage &&
        Boolean(
          targetOutputStage.compareDocumentPosition(runSearchAction) &
            Node.DOCUMENT_POSITION_FOLLOWING
        ) &&
        Boolean(
          runSearchAction.compareDocumentPosition(resultsStage) &
            Node.DOCUMENT_POSITION_FOLLOWING
        ),
      'Target/output precedes Run Search, and Run Search precedes the Home results stage.'
    );

    if (input.targetUrlControlsOnly) {
      clickButton('[data-primary-view="search"]');
      await openDisclosureThroughPoll(
        'details[data-disclosure-key="search-throttles"]',
        'Search throttle settings'
      );
      disclosureFamiliesVerified.push('search-throttles');

      clickButton('[data-search-tab="nerd"]');
      await openDisclosureThroughPoll(
        'details[data-disclosure-key="nerd-template-composer"]',
        'NERD reviewed template composer'
      );
      disclosureFamiliesVerified.push('nerd-template-composer');

      clickButton('[data-search-tab="catalog"]');
      await openDisclosureThroughPoll(
        'details[data-disclosure-key^="operator-catalog:"]',
        'Search operator catalog support'
      );
      disclosureFamiliesVerified.push('operator-catalog');

      clickButton('[data-primary-view="labs"]');
      await openDisclosureThroughPoll(
        'details[data-disclosure-key^="module-settings:"]',
        'Module settings'
      );
      disclosureFamiliesVerified.push('module-settings');

      clickButton('[data-primary-view="home"]');
      const openTargetDisclosure = await waitFor(
        () => document.querySelector('.target-url-disclosure'),
        5000,
        50,
        'the target URL disclosure to return on Home'
      );
      assert(
        openTargetDisclosure instanceof HTMLDetailsElement && openTargetDisclosure.open,
        'The target URL disclosure stays open while navigating between console features.'
      );
      openTargetDisclosure.querySelector('summary')?.click();
      await waitFor(
        () => !openTargetDisclosure.open,
        2000,
        50,
        'the target URL disclosure to close'
      );
      await waitFor(
        () => !openTargetDisclosure.isConnected,
        6000,
        50,
        'the closed target URL disclosure to be replaced by polling'
      );
      const closedTargetDisclosure = document.querySelector('.target-url-disclosure');
      assert(
        closedTargetDisclosure instanceof HTMLDetailsElement && !closedTargetDisclosure.open,
        'The target URL disclosure remains closed on the live DOM after polling.'
      );
      closePersistenceVerified = true;
    }
    const targetUrlControls = {
      disclosureInitiallyClosed: true,
      exactReveal: true,
      exactClipboardPayloads: clipboardWrites.length === targetCopyActions.length,
      exactOutputPreviews: true,
      outputSelectorOptionCount: targetOutputSelect.options.length,
      progressiveHomeOrderVerified: true,
      exactNotices: true,
      actionCount: targetCopyActions.length,
      queryShapeVerified: true,
      focusRetained: true,
      liveStatusRegion: true,
      pollPersistenceVerified,
      refreshPersistenceVerified,
      closePersistenceVerified,
      disclosureFamiliesVerified
    };

    if (input.targetUrlControlsOnly) {
      return {
        mode: 'target-url-controls-only',
        targetUrlControls
      };
    }

    await executeInTarget(
      targetTab.id,
      () => {
        history.replaceState({ blancheTargetControlSmoke: false }, '', '/');
      },
      [],
      'target URL control fixture cleanup'
    );
    await waitFor(
      async () => (await chrome.tabs.get(targetTab.id)).url === `${input.testOrigin}/`,
      10000,
      100,
      'the target tab URL control fixture to be removed'
    );
    await refreshConsole();

    assert(document.querySelectorAll('[data-home-action]').length === 2, 'Home exposes exactly two primary actions.');
    assert(!document.querySelector('#module-list'), 'Technical module controls are not rendered in the primary Home workflow.');

    clickButton('[data-primary-view="search"]');
    await waitFor(
      () => document.querySelector('[data-search-field="targetsText"]') && document.querySelector('[data-search-action="launch"]'),
      10000,
      100,
      'the Search section to render'
    );

    assert(!/Yandex|Baidu/i.test(document.body.innerText), 'Yandex and Baidu are absent from the console.');

    const initialState = await getState();
    const moduleIds = new Set(initialState.modules.map((entry) => entry.descriptor.id));
    for (const expectedModule of ['burp-bridge', 'document-acquisition', 'osint-seed', 'latent-features']) {
      assert(moduleIds.has(expectedModule), `Module is registered: ${expectedModule}`);
    }
    const initialDocumentModule = initialState.modules.find((entry) => entry.descriptor.id === 'document-acquisition');
    assert(initialDocumentModule?.settings?.autoDownloadDocuments === false, 'Document filesystem downloads default to off.');
    assert(initialState.searchExecution?.settings?.sameEngineLaunchDelayMs === 300, 'Same-engine launch spacing defaults to 300 ms.');
    assert(initialState.searchExecution?.settings?.sameQueryRepeatCooldownMs === 300, 'Repeated-query cooldown defaults to 300 ms.');
    assert(initialState.searchExecution?.settings?.maxConcurrentTasks === 1, 'Search task concurrency defaults to one.');
    assert(
      initialState.searchWorkbench?.draft?.selectedEngineIds?.length === 1 &&
        initialState.searchWorkbench.draft.selectedEngineIds[0] === 'google',
      'A fresh Search Workbench selects Google only while leaving the other engines available as options.'
    );

    const scopeProfileId = 'smoke-local-target';
    const scopeTimestamp = new Date().toISOString();
    const scopeTarget = new URL(input.testOrigin);
    const scopeProfile = {
      id: scopeProfileId,
      name: 'Smoke local target',
      scopeNotes: 'Local-only policy used by the extension workflow smoke.',
      scopePolicy: {
        policyId: `engagement:${scopeProfileId}`,
        version: '1',
        defaultDisposition: 'review',
        evaluation: 'highest-priority-exclude-on-tie',
        rules: [
          {
            ruleId: 'smoke-local-origin',
            priority: 100,
            disposition: 'in-scope',
            source: 'capture-target',
            matcher: {
              kind: 'exact-host',
              hostname: scopeTarget.hostname,
              schemes: [scopeTarget.protocol.replace(/:$/, '')],
              ports: [Number(scopeTarget.port)]
            },
            note: 'Permit only the disposable local smoke target.'
          }
        ]
      },
      moduleSettings: Object.fromEntries(
        initialState.modules.map((entry) => [entry.descriptor.id, entry.settings])
      ),
      enabledModuleIds: initialState.modules
        .filter((entry) => entry.enabled)
        .map((entry) => entry.descriptor.id),
      createdAt: scopeTimestamp,
      updatedAt: scopeTimestamp
    };
    await updateEngagementProfiles({
      savedProfiles: [...initialState.engagementProfiles.savedProfiles, scopeProfile]
    });
    await activateEngagementProfile(scopeProfileId);
    const scopedState = await getState();
    assert(
      scopedState.engagementProfiles.activeProfileId === scopeProfileId,
      'Local smoke traffic scope profile is active.'
    );
    const activeScopeProfile = scopedState.engagementProfiles.savedProfiles.find(
      (profile) => profile.id === scopeProfileId
    );
    const activeScopeRule = activeScopeProfile?.scopePolicy?.rules?.find(
      (rule) => rule.ruleId === 'smoke-local-origin'
    );
    assert(
      activeScopeProfile?.scopePolicy?.policyId === `engagement:${scopeProfileId}` &&
        activeScopeProfile.scopePolicy.defaultDisposition === 'review',
      'Active smoke policy retains review-by-default behavior.'
    );
    assert(
      activeScopeRule?.disposition === 'in-scope' &&
        activeScopeRule.source === 'capture-target' &&
        activeScopeRule.matcher?.kind === 'exact-host' &&
        activeScopeRule.matcher.hostname === scopeTarget.hostname &&
        activeScopeRule.matcher.schemes?.includes(scopeTarget.protocol.replace(/:$/, '')) &&
        activeScopeRule.matcher.ports?.includes(Number(scopeTarget.port)),
      'Active smoke policy exactly matches the disposable local target origin.'
    );

    const initialBurpSettings =
      initialState.modules.find((entry) => entry.descriptor.id === 'burp-bridge')?.settings ?? {};
    const initialLatentSettings =
      initialState.modules.find((entry) => entry.descriptor.id === 'latent-features')?.settings ?? {};
    let reviewScopeTab;
    let inScopeTrafficEntry;
    let reviewTrafficEntryCount = 0;
    let inScopeAutomaticAction;
    let reviewAutomaticAction;
    try {
      await updateModuleSettings('burp-bridge', {
        autoCaptureOnNavigation: false,
        autoSendToBurp: false
      });
      await updateModuleSettings('latent-features', {
        autoDiscoverOnNavigation: false,
        probeLoadedLibraries: false,
        checkDependencyAdvisories: false
      });

      const scopeProbeStatus = await executeInTarget(targetTab.id, async () => {
        const response = await fetch('/scope-probe?token=smoke-query-secret', {
          method: 'POST',
          cache: 'no-store',
          headers: {
            authorization: 'Bearer smoke-header-secret',
            'content-type': 'application/x-www-form-urlencoded'
          },
          body: 'password=smoke-body-secret'
        });
        return response.status;
      }, [], 'traffic privacy probe');
      assert(scopeProbeStatus === 404, 'Local in-scope traffic probe completed without an external request.');
      inScopeTrafficEntry = await waitFor(async () => {
        const result = await queryTraffic({
          tabId: targetTab.id,
          scope: 'in-scope',
          limit: 200
        });
        return result.entries.find(
          (entry) =>
            entry.endpoint?.pathTemplate === '/scope-probe' &&
            entry.scope?.matchedRuleIds?.includes('smoke-local-origin')
        );
      }, 10000, 100, 'the local traffic probe to match the active in-scope rule');
      assert(
        inScopeTrafficEntry.scope.disposition === 'in-scope' &&
          inScopeTrafficEntry.scope.policyId === `engagement:${scopeProfileId}` &&
          inScopeTrafficEntry.scope.basis === 'matched-rule',
        'Traffic ledger records the local probe as an active-policy match.'
      );
      assert(
        inScopeTrafficEntry.endpoint.method === 'POST' &&
          inScopeTrafficEntry.endpoint.queryParameterNames.includes('token') &&
          inScopeTrafficEntry.observation.requestHeaderNames.includes('authorization') &&
          inScopeTrafficEntry.observation.requestBodyFieldNames.includes('password'),
        'Traffic ledger retains security-relevant metadata names from the synthetic request.'
      );
      const serializedScopeProbe = JSON.stringify(inScopeTrafficEntry);
      for (const secret of [
        'smoke-query-secret',
        'smoke-header-secret',
        'smoke-body-secret'
      ]) {
        assert(
          !serializedScopeProbe.includes(secret),
          `Traffic ledger does not retain the synthetic request value ${secret}.`
        );
      }

      inScopeAutomaticAction = await runAction(
        'latent-features',
        'discover',
        targetTab.id,
        { automatic: true },
        'background'
      );
      assert(
        ['ok', 'partial'].includes(inScopeAutomaticAction.status),
        'An in-scope background automatic action is allowed.'
      );

      reviewScopeTab = await chrome.tabs.create({
        url: `${input.reviewScopeOrigin}/scope-review-probe`,
        active: false
      });
      assert(typeof reviewScopeTab.id === 'number', 'Local review-default scope tab was created.');
      await waitFor(async () => {
        const tab = await chrome.tabs.get(reviewScopeTab.id);
        return tab.status === 'complete' ? tab : undefined;
      }, 10000, 100, 'the local review-default scope tab to load');
      const reviewTraffic = await queryTraffic({
        tabId: reviewScopeTab.id,
        limit: 50
      });
      reviewTrafficEntryCount = reviewTraffic.entries.length;
      assert(
        reviewTrafficEntryCount === 0,
        'Traffic from an unmatched tab is not silently retained by the target ledger.'
      );

      reviewAutomaticAction = await runAction(
        'latent-features',
        'discover',
        reviewScopeTab.id,
        { automatic: true },
        'background'
      );
      assert(
        reviewAutomaticAction.status === 'error' &&
          reviewAutomaticAction.errors?.some((error) => error.code === 'TRAFFIC_SCOPE_BLOCKED') &&
          / is review under scope policy /.test(reviewAutomaticAction.message),
        'A review-default background automatic action returns TRAFFIC_SCOPE_BLOCKED.'
      );
    } finally {
      if (typeof reviewScopeTab?.id === 'number') {
        await closeTabs([reviewScopeTab]);
      }
      await updateModuleSettings('burp-bridge', initialBurpSettings);
      await updateModuleSettings('latent-features', initialLatentSettings);
    }
    const scopeGateVerification = {
      profileId: scopeProfileId,
      inScopeDisposition: inScopeTrafficEntry.scope.disposition,
      inScopeMatchedRuleIds: inScopeTrafficEntry.scope.matchedRuleIds,
      inScopeAutomaticStatus: inScopeAutomaticAction.status,
      reviewDisposition: activeScopeProfile.scopePolicy.defaultDisposition,
      reviewBasis: 'default',
      reviewTrafficEntryCount,
      reviewAutomaticStatus: reviewAutomaticAction.status,
      reviewAutomaticErrorCodes: reviewAutomaticAction.errors?.map((error) => error.code) ?? []
    };
    const builtInProfileIds = [
      'builtin-osint-public-footprint',
      'builtin-osint-documents-secrets',
      'builtin-osint-infra-certificates'
    ];
    assert(
      builtInProfileIds.every((profileId) =>
        initialState.searchWorkbench.savedProfiles.some((profile) => profile.id === profileId)
      ),
      'Default OSINT search profiles are present in persisted state.'
    );

    clickButton('[data-search-tab="catalog"]');
    const operatorCatalog = await waitFor(() => {
      const root = document.querySelector('[data-search-operator-catalog]');
      const rows = root?.querySelectorAll('[data-catalog-operator]') ?? [];
      return root && rows.length >= 50 ? { root, rowCount: rows.length } : undefined;
    }, 10000, 100, 'the cross-engine operator catalog to render');
    const siteOperatorRow = operatorCatalog.root.querySelector('[data-catalog-operator="site"]');
    assert(siteOperatorRow, 'Operator catalog includes site scope.');
    assert(
      ['google', 'bing', 'duckduckgo'].every((engineId) =>
        siteOperatorRow.querySelector(`[data-catalog-engine="${engineId}"]`)
      ),
      'Operator catalog cross-assesses site scope for Google, Bing, and DuckDuckGo.'
    );
    assert(
      document.querySelector('[data-catalog-operator="cache"] [data-catalog-engine="google"]')
        ?.dataset.catalogStatus === 'deprecated',
      'Operator catalog marks Google cache as deprecated.'
    );

    clickButton('[data-search-tab="profiles"]');
    await waitFor(
      () => document.querySelector('[data-profile-load="builtin-osint-documents-secrets"]'),
      10000,
      100,
      'the built-in OSINT profiles tab to render'
    );
    clickButton('[data-profile-load="builtin-osint-documents-secrets"]');
    await waitFor(
      () =>
        document.querySelector('[data-search-field="queryText"]')?.value.includes('filetype:pdf') &&
        document.querySelector('[data-search-tab="run"]')?.classList.contains('is-active'),
      10000,
      100,
      'a built-in OSINT profile to load into the Run tab'
    );

    const runTargetsField = document.querySelector('[data-search-field="targetsText"]');
    const runQueryField = document.querySelector('[data-search-field="queryText"]');
    assert(runTargetsField && runQueryField, 'Run tab exposes target and query fields.');
    dispatchInput(runTargetsField, 'example.test');
    dispatchInput(runQueryField, 'filetype:pdf');
    clickButton('[data-search-tab="configure"]');
    await waitFor(
      () => document.querySelector('[data-search-field="name"]'),
      10000,
      100,
      'the search Configure tab to expose profile controls'
    );
    dispatchInput(document.querySelector('[data-search-field="name"]'), 'Smoke recon sweep');

    const customLabel = document.querySelector('[data-custom-field="label"]');
    const customTemplate = document.querySelector('[data-custom-field="template"]');
    const customDescription = document.querySelector('[data-custom-field="description"]');
    const googleCustomEngine = document.querySelector('[data-custom-engine-id="google"]');
    assert(customLabel && customTemplate && googleCustomEngine, 'Custom operator composer is present.');
    dispatchInput(customLabel, 'smoke-title');
    dispatchInput(customTemplate, 'intitle:"smoke"');
    if (customDescription) {
      dispatchInput(customDescription, 'Smoke-only operator used by automated QA.');
    }
    googleCustomEngine.checked = true;
    googleCustomEngine.dispatchEvent(new Event('change', { bubbles: true }));
    clickButton('[data-search-action="add-custom-operator"]');
    await waitFor(
      async () => (await getState()).searchWorkbench.customOperators.some((entry) => entry.label === 'smoke-title'),
      10000,
      100,
      'the custom search operator to persist'
    );
    await waitFor(
      () => document.querySelector('[data-search-action="save-profile"]')?.disabled === false,
      10000,
      100,
      'the search profile save button to re-enable'
    );

    clickButton('[data-search-action="save-profile"]');
    await waitFor(
      async () => (await getState()).searchWorkbench.savedProfiles.some((entry) => entry.name === 'Smoke recon sweep'),
      10000,
      100,
      'the search profile to persist'
    );

    clickButton('[data-search-tab="run"]');
    await waitFor(
      () => document.querySelector('[data-search-action="launch"]')?.disabled === false,
      10000,
      100,
      'the search Run tab to show launch controls'
    );
    clickButton('[data-search-action="launch"]');
    const trackedSearch = await waitFor(async () => {
      const state = await getState();
      const session = state.searchExecution?.sessions?.[0];
      return session?.tasks?.length >= 3 ? session : undefined;
    }, 10000, 100, 'tracked search session');
    assert(
      trackedSearch.tasks.every((task) => !/yandex|baidu/i.test(task.searchUrl ?? '')),
      'Tracked search did not create Yandex or Baidu tasks.'
    );

    clickButton('[data-search-tab="suite"]');
    await waitFor(
      () => document.querySelector('[data-dork-suite]'),
      10000,
      100,
      'the engine-aware Dork Suite tab to render'
    );
    dispatchInput(
      document.querySelector('[data-search-field="targetsText"]'),
      new URL(input.testOrigin).hostname
    );
    for (const categoryId of [
      'auth-surfaces',
      'indexed-documents',
      'api-surface',
      'client-artifacts',
      'directory-listings'
    ]) {
      const categoryField = document.querySelector(`[data-suite-category="${categoryId}"]`);
      if (categoryField?.checked) {
        categoryField.click();
        await sleep(40);
      }
    }
    dispatchInput(document.querySelector('[data-suite-field="maxQueries"]'), '5');
    const dorkPreview = await waitFor(() => {
      const entries = [...document.querySelectorAll('[data-dork-entry]')].map((entry) => ({
        id: entry.dataset.dorkEntry ?? '',
        query: entry.querySelector('.search-code')?.textContent?.trim() ?? ''
      }));
      const dialects = [...new Set(entries
        .map((entry) => /^dork_(google|bing|duckduckgo)_/.exec(entry.id)?.[1])
        .filter(Boolean))];
      return entries.length === 5 &&
        entries.every((entry) => entry.query.includes('site:127.0.0.1')) &&
        dialects.length === 3
        ? { entryCount: entries.length, entries, dialects }
        : undefined;
    }, 10000, 100, 'a bounded cross-engine dork preview');
    clickButton('[data-search-action="launch-suite"]');
    const dorkSuite = await waitFor(async () => {
      const executionState = await getState();
      const session = executionState.searchExecution?.sessions?.find(
        (entry) => entry.mode === 'dork-suite'
      );
      return session?.tasks?.length === 5 ? session : undefined;
    }, 10000, 100, 'the generated Dork Suite session trace');
    const dorkDialects = [...new Set(dorkSuite.tasks.map((task) => task.dialect))];
    assert(
      dorkSuite.catalogReviewedAt === '2026-09-09' &&
        [
          ['google', 'after'],
          ['bing', 'prefer'],
          ['duckduckgo', 'ddg-semantic']
        ].every(([dialect, advancedOperatorId]) =>
          dorkSuite.tasks.some(
            (task) =>
              task.dialect === dialect &&
              task.operatorIds?.includes(advancedOperatorId)
          )
        ) &&
        dorkSuite.tasks.every(
          (task) =>
            task.dorkId &&
            task.operatorIds?.includes('site') &&
            task.query?.includes('site:127.0.0.1')
        ),
      'Dork Suite persists catalog, exact-query, and operator metadata for every engine dialect.'
    );

    await chrome.tabs.update(targetTab.id, { active: true });
    await refreshConsole();
    clickButton('[data-search-tab="nerd"]');
    await waitFor(
      () =>
        document.querySelector('[data-nerd-mode]') &&
        document.querySelector('[data-search-action="discover-nerd"]')?.disabled === false,
      10000,
      100,
      'the NERD mode tab and page-scan control to become ready'
    );
    clickButton('[data-search-action="discover-nerd"]');
    const getCandidateCard = await waitFor(() => {
      const cards = [...document.querySelectorAll('[data-nerd-candidate-card]')];
      return cards.find(
        (card) =>
          /GET/.test(card.textContent ?? '') &&
          card.querySelector('.search-code')?.textContent?.trim() === '#site-search-input'
      );
    }, 10000, 100, 'NERD mode to discover the local GET search form');
    const targetUrlBeforeSelectorChecks = (await chrome.tabs.get(targetTab.id)).url;
    const highlightButton = getCandidateCard.querySelector('[data-nerd-highlight]');
    assert(highlightButton, 'The discovered GET search candidate exposes a page highlight control.');
    highlightButton.click();
    await waitFor(
      () =>
        /Highlighted .*target page's top frame/i.test(
          document.querySelector('[role="status"]')?.textContent ?? ''
        ),
      5000,
      50,
      'the candidate highlight action to report success'
    );
    const highlightObservation = {
      highlighted: true,
      url: (await chrome.tabs.get(targetTab.id)).url
    };
    if (
      !highlightObservation.highlighted ||
      highlightObservation.url !== targetUrlBeforeSelectorChecks
    ) {
      throw new Error(
        `Site Search highlight mismatch: ${JSON.stringify({
          targetUrlBeforeSelectorChecks,
          highlightObservation,
          notice: document.querySelector('[role="status"]')?.textContent ?? ''
        })}`
      );
    }

    clickButton('[data-search-action="pick-nerd"]');
    await waitFor(
      () =>
        executeInTarget(
          targetTab.id,
          () =>
            document.querySelector('#site-search-input')?.hasAttribute(
              'data-blanche-search-picker'
            ) === true,
          [],
          'Site Search picker activation verification'
        ),
      5000,
      50,
      'the top-frame Site Search picker to mark eligible inputs'
    );
    const pickerClickObservation = await executeInTarget(
      targetTab.id,
      () => {
        const before = location.href;
        const input = document.querySelector('#site-search-input');
        input?.dispatchEvent(new PointerEvent('pointerover', { bubbles: true }));
        input?.click();
        return {
          clicked: Boolean(input),
          before,
          after: location.href
        };
      },
      [],
      'Site Search top-frame picker selection'
    );
    await waitFor(
      () => {
        const candidate = [...document.querySelectorAll('[data-nerd-candidate-card]')].find(
          (card) => card.querySelector('.search-code')?.textContent?.trim() === '#site-search-input'
        );
        const pickerButton = document.querySelector('[data-search-action="pick-nerd"]');
        return candidate && pickerButton?.disabled === false ? candidate : undefined;
      },
      10000,
      100,
      'the picked top-frame Site Search candidate to return to the review list'
    );
    const targetUrlAfterPicker = (await chrome.tabs.get(targetTab.id)).url;
    const pickerMarkerRemaining = await executeInTarget(
      targetTab.id,
      () => document.querySelector('[data-blanche-search-picker]') !== null,
      [],
      'Site Search picker cleanup verification'
    );
    assert(
      pickerClickObservation.clicked &&
        pickerClickObservation.before === pickerClickObservation.after &&
        targetUrlAfterPicker === targetUrlBeforeSelectorChecks &&
        pickerMarkerRemaining === false,
      'The top-frame picker captures the search-field click, avoids form submission or navigation, and removes its page markers.'
    );

    dispatchInput(
      document.querySelector('[data-suite-field="keywordsText"]'),
      'acquisition project\nlegacy portal'
    );
    dispatchInput(document.querySelector('[data-suite-field="maxQueries"]'), '24');
    const portablePreview = await waitFor(() => {
      const entries = [...document.querySelectorAll('[data-dork-entry]')].map((entry) => ({
        id: entry.dataset.dorkEntry ?? '',
        query: entry.querySelector('.search-code')?.textContent?.trim() ?? ''
      }));
      const ids = new Set(entries.map((entry) => entry.id));
      const firstTermCount = entries.filter((entry) => entry.query.includes('acquisition project')).length;
      const secondTermCount = entries.filter((entry) => entry.query.includes('legacy portal')).length;
      const roundRobinTerms = entries.map((entry) =>
        entry.query.includes('acquisition project')
          ? 'acquisition project'
          : entry.query.includes('legacy portal')
            ? 'legacy portal'
            : ''
      );
      return entries.length === 4 &&
        ids.size === entries.length &&
        firstTermCount === 2 &&
        secondTermCount === 2 &&
        JSON.stringify(roundRobinTerms) ===
          JSON.stringify([
            'acquisition project',
            'legacy portal',
            'acquisition project',
            'legacy portal'
          ]) &&
        entries.every((entry) => !/\bsite:/i.test(entry.query))
        ? { entries, firstTermCount, secondTermCount, roundRobinTerms }
        : undefined;
    }, 10000, 100, 'the two-keyword portable Site Search plan to render without site scope syntax');

    const currentGetCandidateCard = [...document.querySelectorAll('[data-nerd-candidate-card]')].find(
      (card) => card.querySelector('.search-code')?.textContent?.trim() === '#site-search-input'
    );
    const getCandidateButton = currentGetCandidateCard?.querySelector('[data-nerd-candidate]');
    assert(getCandidateButton, 'The picked GET Site Search candidate remains selectable.');
    getCandidateButton.click();
    const savedGetNerdSurface = await waitFor(async () => {
      const executionState = await getState();
      return executionState.searchWorkbench.nerdSurfaces.find(
        (surface) => surface.mode === 'get' && surface.queryParam === 'q'
      );
    }, 10000, 100, 'the selected NERD surface to persist');
    await waitForSelectedNerdSurface(savedGetNerdSurface.id, 'the saved GET NERD surface');

    const postCandidateButton = await waitFor(() => {
      const cards = [...document.querySelectorAll('[data-nerd-candidate-card]')];
      const postCard = cards.find((card) => /POST/.test(card.textContent ?? ''));
      return postCard?.querySelector('[data-nerd-candidate]') ?? undefined;
    }, 10000, 100, 'NERD mode to discover the local POST search form');
    postCandidateButton.click();
    const savedPostNerdSurface = await waitFor(async () => {
      const executionState = await getState();
      return executionState.searchWorkbench.nerdSurfaces.find(
        (surface) =>
          surface.mode === 'form' &&
          surface.method === 'post' &&
          surface.inputSelector === '#site-post-search-input'
      );
    }, 10000, 100, 'the selected POST NERD surface to persist');
    assert(
      savedPostNerdSurface.fixedParams?.corpus === 'knowledge' &&
        !Object.keys(savedPostNerdSurface.fixedParams ?? {}).some((key) => /csrf|token/i.test(key)),
      'NERD discovery preserves the safe POST selector while excluding sensitive fixed fields.'
    );
    await waitForSelectedNerdSurface(savedPostNerdSurface.id, 'the saved POST NERD surface');

    const dynamicCandidateButton = await waitFor(() => {
      const cards = [...document.querySelectorAll('[data-nerd-candidate-card]')];
      const dynamicCard = cards.find((card) => /DYNAMIC/.test(card.textContent ?? ''));
      return dynamicCard?.querySelector('[data-nerd-candidate]') ?? undefined;
    }, 10000, 100, 'NERD mode to discover the local JavaScript-driven search widget');
    dynamicCandidateButton.click();
    const savedDynamicNerdSurface = await waitFor(async () => {
      const executionState = await getState();
      return executionState.searchWorkbench.nerdSurfaces.find(
        (surface) =>
          surface.mode === 'form' &&
          surface.method === 'dynamic' &&
          surface.inputSelector === '#site-dynamic-search-input'
      );
    }, 10000, 100, 'the selected JavaScript-driven NERD surface to persist');
    assert(
      Object.keys(savedDynamicNerdSurface.fixedParams ?? {}).length === 0,
      'NERD discovery stores no unrelated page state for the JavaScript-driven surface.'
    );
    await waitForSelectedNerdSurface(
      savedDynamicNerdSurface.id,
      'the saved JavaScript-driven NERD surface'
    );

    await selectSavedNerdSurface(savedGetNerdSurface.id, 'the GET NERD surface');
    clickButton('[data-search-action="launch-nerd"]');
    const nerdGetSuite = await waitFor(async () => {
      const executionState = await getState();
      const session = executionState.searchExecution?.sessions?.find(
        (entry) =>
          entry.mode === 'nerd' &&
          entry.tasks?.some((task) => task.nerdSurface?.id === savedGetNerdSurface.id)
      );
      return session?.tasks?.length > 0 &&
        session.tasks.every((task) =>
          ['completed-results', 'completed-no-results', 'manual-required', 'failed'].includes(
            task.status
          )
        )
        ? session
        : undefined;
    }, 45000, 150, 'the two-keyword local Site Search suite to reach terminal states');
    if (
      nerdGetSuite.tasks.length !== portablePreview.entries.length ||
      nerdGetSuite.tasks.some((task) => task.status !== 'completed-results' || task.resultCount < 1)
    ) {
      throw new Error(
        `Site Search terminal-state mismatch: ${JSON.stringify(
          nerdGetSuite.tasks.map((task) => ({
            id: task.dorkId,
            query: task.query,
            status: task.status,
            resultCount: task.resultCount,
            error: task.error
          }))
        )}`
      );
    }
    const nerdGetTask = nerdGetSuite.tasks[0];
    assert(
      nerdGetTask.nerdSurface?.id === savedGetNerdSurface.id &&
        nerdGetTask.nerdSurface?.mode === 'get' &&
        nerdGetTask.searchUrl.includes('section=all') &&
        !nerdGetTask.searchUrl.includes('csrf') &&
        nerdGetTask.results.some((result) => result.url.includes('/docs/readme.txt')) &&
        nerdGetSuite.tasks.every(
          (task) =>
            task.target === new URL(input.testOrigin).hostname &&
            JSON.stringify(task.targets) ===
              JSON.stringify([new URL(input.testOrigin).hostname])
        ) &&
        portablePreview.entries.every((previewEntry) =>
          nerdGetSuite.tasks.some(
            (task) => task.dorkId === previewEntry.id && task.query === previewEntry.query
          )
        ),
      'Site Search submitted every reviewed keyword/template pair, retained safe fixed parameters, and parsed results.'
    );
    await refreshConsole();
    const siteSearchFingerprintRoot = await waitFor(() => {
      const root = document.querySelector('[data-site-search-fingerprint]');
      const text = root?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
      return root && !/Not run/i.test(text) ? { text } : undefined;
    }, 10000, 100, 'the completed aggregate Site Search behavior fingerprint to render');
    if (
      !new RegExp(`${portablePreview.entries.length}\\s*bounded probes`, 'i').test(
        siteSearchFingerprintRoot.text
      ) ||
      !/results observed/i.test(siteSearchFingerprintRoot.text) ||
      !/archives/i.test(siteSearchFingerprintRoot.text)
    ) {
      throw new Error(
        `Site Search fingerprint mismatch: ${JSON.stringify(siteSearchFingerprintRoot.text)}`
      );
    }
    const siteSearchFingerprint = siteSearchFingerprintRoot;
    assert(
      !/Algolia|Elasticsearch|OpenSearch|Solr/i.test(siteSearchFingerprint.text),
      'The aggregate Site Search fingerprint reports observed behavior without inventing a backend vendor.'
    );

    if (input.siteSearchOnly) {
      return {
        search: {
          freshDefaultEngineIds: initialState.searchWorkbench.draft.selectedEngineIds,
          nerdSuite: {
            taskCount: nerdGetSuite.tasks.length,
            mode: nerdGetSuite.mode,
            surfaceMode: nerdGetTask.nerdSurface?.mode,
            surfaceMethod: nerdGetTask.nerdSurface?.method,
            resultCount: nerdGetSuite.tasks.reduce((total, task) => total + task.resultCount, 0),
            resultUrls: nerdGetSuite.tasks.flatMap((task) =>
              task.results.map((result) => result.url)
            ),
            portablePreview: portablePreview.entries,
            keywordPassCounts: {
              acquisitionProject: portablePreview.firstTermCount,
              legacyPortal: portablePreview.secondTermCount
            },
            roundRobinTerms: portablePreview.roundRobinTerms,
            surfaceHostBound: nerdGetSuite.tasks.every(
              (task) =>
                task.target === new URL(input.testOrigin).hostname &&
                JSON.stringify(task.targets) ===
                  JSON.stringify([new URL(input.testOrigin).hostname])
            ),
            candidateHighlightVerified:
              highlightObservation.highlighted &&
              highlightObservation.url === targetUrlBeforeSelectorChecks,
            topFramePickerVerified:
              pickerClickObservation.clicked &&
              targetUrlAfterPicker === targetUrlBeforeSelectorChecks &&
              pickerMarkerRemaining === false,
            fingerprintRendered:
              /Observed behavior fingerprint/i.test(siteSearchFingerprint.text) &&
              /results observed/i.test(siteSearchFingerprint.text)
          }
        }
      };
    }

    dispatchInput(document.querySelector('[data-suite-field="maxQueries"]'), '1');

    await selectSavedNerdSurface(savedPostNerdSurface.id, 'the POST NERD surface');
    clickButton('[data-search-action="launch-nerd"]');
    const nerdPostSuite = await waitFor(async () => {
      const executionState = await getState();
      const session = executionState.searchExecution?.sessions?.find(
        (entry) =>
          entry.mode === 'nerd' &&
          entry.tasks?.some((task) => task.nerdSurface?.id === savedPostNerdSurface.id)
      );
      const task = session?.tasks?.[0];
      return task?.status === 'completed-results' && task.resultCount > 0
        ? session
        : undefined;
    }, 30000, 150, 'the local POST NERD search to return tracked results');
    const nerdPostTask = nerdPostSuite.tasks[0];
    assert(
      nerdPostTask.nerdSurface?.mode === 'form' &&
        nerdPostTask.nerdSurface?.method === 'post' &&
        nerdPostTask.nerdFormSubmission?.inputSelector === '#site-post-search-input' &&
        !JSON.stringify(nerdPostTask).includes('must-not-be-reported') &&
        nerdPostTask.results.some((result) => result.url.includes('from=nerd-post')),
      'NERD mode replays the discovered POST form, keeps its trace sanitized, and parses results.'
    );

    await selectSavedNerdSurface(
      savedDynamicNerdSurface.id,
      'the JavaScript-driven NERD surface'
    );
    clickButton('[data-search-action="launch-nerd"]');
    const nerdDynamicSuite = await waitFor(async () => {
      const executionState = await getState();
      const session = executionState.searchExecution?.sessions?.find(
        (entry) =>
          entry.mode === 'nerd' &&
          entry.tasks?.some((task) => task.nerdSurface?.id === savedDynamicNerdSurface.id)
      );
      const task = session?.tasks?.[0];
      return task?.status === 'completed-results' && task.resultCount > 0
        ? session
        : undefined;
    }, 30000, 150, 'the JavaScript-driven NERD search to return tracked results');
    const nerdDynamicTask = nerdDynamicSuite.tasks[0];
    assert(
      nerdDynamicTask.nerdSurface?.mode === 'form' &&
        nerdDynamicTask.nerdSurface?.method === 'dynamic' &&
        nerdDynamicTask.nerdFormSubmission?.inputSelector === '#site-dynamic-search-input' &&
        !JSON.stringify(nerdDynamicTask).includes('must-not-be-reported') &&
        nerdDynamicTask.results.some((result) => result.url.includes('from=nerd-dynamic')),
      'NERD mode drives the JavaScript widget, keeps its trace sanitized, and parses results.'
    );

    document.querySelector('.nerd-template-composer > summary')?.click();
    dispatchInput(
      document.querySelector('[data-nerd-field="template-name"]'),
      'Smoke reviewed URL template'
    );
    dispatchInput(
      document.querySelector('[data-nerd-field="url-template"]'),
      `${input.testOrigin}/search?section=template&q={query}`
    );
    clickButton('[data-search-action="save-nerd-template"]');
    const savedTemplateNerdSurface = await waitFor(async () => {
      const executionState = await getState();
      return executionState.searchWorkbench.nerdSurfaces.find(
        (surface) => surface.mode === 'template' && surface.name === 'Smoke reviewed URL template'
      );
    }, 10000, 100, 'the reviewed URL-template NERD surface to persist');
    await waitForSelectedNerdSurface(
      savedTemplateNerdSurface.id,
      'the reviewed URL-template NERD surface'
    );
    clickButton('[data-search-action="launch-nerd"]');
    const nerdTemplateSuite = await waitFor(async () => {
      const executionState = await getState();
      const session = executionState.searchExecution?.sessions?.find(
        (entry) =>
          entry.mode === 'nerd' &&
          entry.tasks?.some((task) => task.nerdSurface?.id === savedTemplateNerdSurface.id)
      );
      const task = session?.tasks?.[0];
      return task &&
        ['completed-results', 'completed-no-results', 'manual-required', 'failed'].includes(
          task.status
        )
        ? session
        : undefined;
    }, 30000, 150, 'the reviewed URL-template NERD search to reach a terminal state');
    const nerdTemplateTask = nerdTemplateSuite.tasks[0];
    if (nerdTemplateTask.status !== 'completed-results' || nerdTemplateTask.resultCount < 1) {
      throw new Error(
        `Reviewed URL-template Site Search mismatch: ${JSON.stringify({
          query: nerdTemplateTask.query,
          searchUrl: nerdTemplateTask.searchUrl,
          status: nerdTemplateTask.status,
          resultCount: nerdTemplateTask.resultCount,
          error: nerdTemplateTask.error
        })}`
      );
    }
    assert(
      nerdTemplateTask.nerdSurface?.mode === 'template' &&
        nerdTemplateTask.searchUrl.includes('section=template') &&
        !nerdTemplateTask.searchUrl.includes('{query}') &&
        nerdTemplateTask.results.some((result) => result.url.includes('/docs/readme.txt')),
      'NERD mode substitutes and runs the reviewed URL template with parsed result output.'
    );

    await updateModuleSettings('burp-bridge', {
      defaultMode: 'instrumented',
      reloadBeforeCollect: true,
      autoCaptureOnNavigation: false,
      autoSendToBurp: true,
      burpIngestUrl: input.ingestUrl,
      resourceEntryLimit: 500,
      cacheEntryLimit: 100,
      storageValueLimit: 800
    });
    const bridgeCollect = await runAction('burp-bridge', 'collect', targetTab.id);
    assert(['ok', 'partial'].includes(bridgeCollect.status), 'Burp Bridge collect returns a handled status.');
    assert(bridgeCollect.export?.collection?.mode === 'instrumented', 'Burp Bridge collect used instrumented mode.');
    await waitForTargetReady(targetTab.id);

    await updateModuleSettings('burp-bridge', {
      defaultMode: 'passive',
      reloadBeforeCollect: false,
      autoSendToBurp: false,
      burpIngestUrl: input.ingestUrl
    });
    const bridgePassive = await runAction('burp-bridge', 'collectPassive', targetTab.id);
    assert(bridgePassive.export?.collection?.mode === 'passive', 'Burp Bridge passive action used passive mode.');
    assert(
      bridgePassive.warnings?.some((warning) => warning.code === 'PASSIVE_MODE_PROVENANCE_LIMIT'),
      'Passive collection surfaces provenance warnings.'
    );
    await updateModuleSettings('latent-features', {
      autoDiscoverOnNavigation: false,
      probeLoadedLibraries: true,
      includeThirdPartyLibraries: false,
      libraryThreadCount: 1,
      libraryDelayMs: 100,
      maxLibrariesPerScan: 4,
      maxLibraryBytes: 262144,
      maxTotalLibraryBytes: 524288,
      maxCandidates: 100,
      javascriptObservationMs: 500,
      reloadAfterProbe: true
    });
    const rawJavascriptTab = await chrome.tabs.create({
      url: `${input.testOrigin}/app.js`,
      active: false
    });
    assert(rawJavascriptTab.id, 'The raw JavaScript smoke tab has an identifier.');
    let rawJavascriptAssessment;
    try {
      await waitFor(
        async () => (await chrome.tabs.get(rawJavascriptTab.id)).status === 'complete',
        10000,
        100,
        'the raw JavaScript document tab to finish loading'
      );
      const rawJavascriptDiscovery = await runAction(
        'latent-features',
        'discover',
        rawJavascriptTab.id
      );
      assert(
        ['ok', 'partial'].includes(rawJavascriptDiscovery.status),
        'Raw JavaScript document analysis completes.'
      );
      const rawJavascriptState = await getState();
      rawJavascriptAssessment =
        rawJavascriptState.latentFeatureWorkbench?.lastScan?.scriptAssessments?.find(
          (assessment) => assessment.artifact?.sourceKind === 'document'
        );
      assert(
        rawJavascriptAssessment?.artifact?.sourceKind === 'document' &&
          new URL(rawJavascriptAssessment.artifact.sourceUrl).pathname === '/app.js' &&
          /^[a-f0-9]{64}$/.test(rawJavascriptAssessment.artifact.sha256 ?? ''),
        'A directly displayed JavaScript response is retained as a hashed document source.'
      );
      assertAssessmentEvidence(rawJavascriptAssessment, 'Raw JavaScript document assessment');
    } finally {
      await chrome.tabs.remove(rawJavascriptTab.id).catch(() => {});
    }

    const queuedDiscoveryLoadCountBefore = await executeInTarget(
      targetTab.id,
      () => Number(sessionStorage.getItem('blanche-smoke-load-count') ?? '0'),
      [],
      'queued passive/startup action load count baseline'
    );
    const [queuedPassiveDiscovery, queuedStartupObservation] = await Promise.all([
      runAction('latent-features', 'discover', targetTab.id),
      runAction('latent-features', 'testJavascript', targetTab.id)
    ]);
    assert(
      ['ok', 'partial'].includes(queuedPassiveDiscovery.status) &&
        queuedPassiveDiscovery.data?.javascriptTestRunId === null,
      'A passive analysis keeps its own result when a startup observation is queued behind it.'
    );
    assert(
      ['ok', 'partial'].includes(queuedStartupObservation.status) &&
        typeof queuedStartupObservation.data?.javascriptTestRunId === 'string',
      'A queued startup observation runs after the passive analysis and returns its own test run.'
    );
    await waitForTargetReady(targetTab.id);
    const queuedDiscoveryLoadCountAfter = await executeInTarget(
      targetTab.id,
      () => Number(sessionStorage.getItem('blanche-smoke-load-count') ?? '0'),
      [],
      'queued passive/startup action load count verification'
    );
    const queuedDiscoveryState = await getState();
    assert(
      queuedDiscoveryLoadCountAfter === queuedDiscoveryLoadCountBefore + 1,
      'Concurrent passive and startup actions serialize and cause exactly one reload.'
    );
    assert(
      queuedDiscoveryState.latentFeatureWorkbench?.lastJavascriptTest?.testRunId ===
        queuedStartupObservation.data.javascriptTestRunId,
      'The queued startup result, rather than the passive result, remains the current test trace.'
    );

    const passiveLoadCountBefore = await executeInTarget(
      targetTab.id,
      () => ({
        count: Number(sessionStorage.getItem('blanche-smoke-load-count') ?? '0'),
        ready: document.body.dataset.blancheSmokeReady === 'true',
        sessionCount: sessionStorage.getItem('blanche-smoke-load-count'),
        appScriptLoaded: performance.getEntriesByType('resource').some((entry) =>
          new URL(entry.name).pathname === '/app.js'
        )
      }),
      [],
      'passive JavaScript analysis load count baseline'
    );
    const latentDiscovery = await runAction('latent-features', 'discover', targetTab.id);
    assert(['ok', 'partial'].includes(latentDiscovery.status), 'Latent feature discovery completes.');
    assert(latentDiscovery.data?.libraryThreadCount === 1, 'Latent feature scan keeps one worker.');
    assert(latentDiscovery.data?.libraryDelayMs === 100, 'Latent feature scan reports global spacing.');
    const latentState = await getState();
    const latentCandidates = latentState.latentFeatureWorkbench?.lastScan?.candidates ?? [];
    const passiveScriptAssessments =
      latentState.latentFeatureWorkbench?.lastScan?.scriptAssessments ?? [];
    const passiveAppAssessment = passiveScriptAssessments.find((assessment) => {
      const rawUrl = assessment.artifact?.finalUrl ?? assessment.artifact?.sourceUrl;
      try {
        return new URL(rawUrl).pathname === '/app.js';
      } catch {
        return false;
      }
    });
    const passiveLoadCountAfter = await executeInTarget(
      targetTab.id,
      () => ({
        count: Number(sessionStorage.getItem('blanche-smoke-load-count') ?? '0'),
        ready: document.body.dataset.blancheSmokeReady === 'true',
        sessionCount: sessionStorage.getItem('blanche-smoke-load-count')
      }),
      [],
      'passive JavaScript analysis load count verification'
    );
    assert(passiveScriptAssessments.length > 0, 'Passive analysis retains delivered-script assessments.');
    assert(passiveAppAssessment, 'Passive analysis includes the already-loaded /app.js body.');
    assert(
      passiveLoadCountAfter.count === passiveLoadCountBefore.count,
      'Passive JavaScript analysis performs static source acquisition without reloading the page.'
    );
    assert(
      latentState.latentFeatureWorkbench?.lastJavascriptTest === undefined,
      'Passive analysis does not create an active startup-observation run.'
    );
    assert(
      passiveAppAssessment.kind === 'blanche.script-purpose-analysis' &&
        passiveAppAssessment.rubricVersion === 'blanche.script-purpose-rubric.v1' &&
        /^[a-f0-9]{64}$/.test(passiveAppAssessment.artifact?.sha256 ?? '') &&
        passiveAppAssessment.reviewPriority?.isVulnerabilitySeverity === false,
      'The /app.js assessment retains its rubric, content identity, and review-priority contract.'
    );
    assertAssessmentEvidence(passiveAppAssessment, 'Passive /app.js assessment');
    assert(
      latentCandidates.some((candidate) => candidate.key === 'smokeWebpackFeature'),
      'Latent feature scan finds a shipped bundle callsite.'
    );
    assert(
      latentCandidates.some((candidate) => candidate.key === 'remotePreviewPanel'),
      'Latent feature scan finds delivered runtime configuration.'
    );
    assert(
      latentCandidates.some((candidate) => candidate.key === 'pairedResponseFeature'),
      'Latent feature scan correlates a response key with its binary state field.'
    );

    const startupLoadCountBefore = await executeInTarget(
      targetTab.id,
      () => ({
        count: Number(sessionStorage.getItem('blanche-smoke-load-count') ?? '0'),
        ready: document.body.dataset.blancheSmokeReady === 'true',
        sessionCount: sessionStorage.getItem('blanche-smoke-load-count')
      }),
      [],
      'bounded startup observation load count baseline'
    );
    const javascriptStartupAction = await runAction(
      'latent-features',
      'testJavascript',
      targetTab.id
    );
    assert(
      ['ok', 'partial'].includes(javascriptStartupAction.status),
      'The in-scope bounded JavaScript startup observation completes with a handled status.'
    );
    await waitForTargetReady(targetTab.id);
    const startupLoadCountAfter = await executeInTarget(
      targetTab.id,
      () => ({
        count: Number(sessionStorage.getItem('blanche-smoke-load-count') ?? '0'),
        ready: document.body.dataset.blancheSmokeReady === 'true',
        sessionCount: sessionStorage.getItem('blanche-smoke-load-count')
      }),
      [],
      'bounded startup observation single-reload verification'
    );
    assert(
      startupLoadCountAfter.count === startupLoadCountBefore.count + 1,
      `The bounded startup observation reloads the target exactly once (before ${JSON.stringify(startupLoadCountBefore)}, after ${JSON.stringify(startupLoadCountAfter)}).`
    );

    const javascriptState = await getState();
    const activeScriptAssessments =
      javascriptState.latentFeatureWorkbench?.lastScan?.scriptAssessments ?? [];
    const activeAppAssessment = activeScriptAssessments.find((assessment) => {
      const rawUrl = assessment.artifact?.finalUrl ?? assessment.artifact?.sourceUrl;
      try {
        return new URL(rawUrl).pathname === '/app.js';
      } catch {
        return false;
      }
    });
    const javascriptStartupTest = javascriptState.latentFeatureWorkbench?.lastJavascriptTest;
    assert(activeAppAssessment, 'The active observation preserves the /app.js assessment.');
    assertAssessmentEvidence(activeAppAssessment, 'Active /app.js assessment');
    assert(
      javascriptStartupTest?.scopeDisposition === 'in-scope' &&
        javascriptStartupTest.scopePolicyId === `engagement:${scopeProfileId}` &&
        javascriptStartupTest.reloadTriggered === true &&
        javascriptStartupTest.instrumentationAvailable === true &&
        javascriptStartupTest.instrumentationIntegrity === 'page-world-unverified',
      'The persisted startup observation records explicit scope, one reload, and instrumentation.'
    );
    assert(
      activeAppAssessment.behaviorClaims.every((claim) => claim.maturity < 3),
      'Unverified page-world messages do not raise per-script behavior maturity to runtime level 3.'
    );
    assert(
      javascriptStartupTest?.scanId === javascriptState.latentFeatureWorkbench?.lastScan?.scanId &&
        javascriptStartupTest.artifactFingerprints?.length === activeScriptAssessments.length,
      'The persisted startup observation is bound to the exact source scan and artifact hashes.'
    );
    assert(
      javascriptStartupTest?.runtimeStats?.eventCount > 0 &&
        javascriptStartupTest.runtimeStats.lifecycleCount > 0 &&
        javascriptStartupTest.runtimeStats.networkRequestCount > 0 &&
        javascriptStartupTest.runtimeStats.domMutationCount > 0 &&
        javascriptStartupTest.runtimeStats.storageWriteCount > 0 &&
        javascriptStartupTest.runtimeStats.workerCount > 0 &&
        javascriptStartupTest.runtimeStats.trafficEntryCount > 0,
      'The startup observation retains lifecycle, network, DOM, storage, worker, and traffic evidence.'
    );
    const expectedCellStatuses = new Map([
      ['traffic-window', 'observed'],
      ['behavior-network', 'observed'],
      ['behavior-dom-ui', 'observed-unverified'],
      ['behavior-client-storage', 'observed-unverified'],
      ['behavior-persistence-background-realtime', 'observed-unverified']
    ]);
    for (const [testId, expectedStatus] of expectedCellStatuses) {
      const cell = javascriptStartupTest?.cells?.find((entry) => entry.testId === testId);
      assert(
        cell?.status === expectedStatus && cell.evidenceRefs?.length > 0,
        `Startup observation cell ${testId} retains ${expectedStatus} evidence references.`
      );
    }
    const retainedTestEvidenceIds = new Set(
      (javascriptStartupTest?.evidence ?? []).map((entry) => entry.evidenceId)
    );
    assert(
      retainedTestEvidenceIds.size > 0 &&
        javascriptStartupTest.cells
          .flatMap((cell) => cell.evidenceRefs ?? [])
          .every((evidenceId) => retainedTestEvidenceIds.has(evidenceId)),
      'Every startup-observation cell evidence reference resolves to a persisted sanitized record.'
    );
    assert(
      javascriptStartupTest.evidence.some((entry) => entry.type === 'traffic-ledger-entry'),
      'Extension-recorded startup traffic is copied into the test as resolvable ledger evidence.'
    );
    const activeArtifactIds = new Set(
      activeScriptAssessments.map((assessment) => assessment.artifact?.artifactId).filter(Boolean)
    );
    assert(
      javascriptStartupTest.artifactIds.length > 0 &&
        javascriptStartupTest.artifactIds.every((artifactId) => activeArtifactIds.has(artifactId)) &&
        javascriptStartupTest.cells
          .flatMap((cell) => cell.artifactIds ?? [])
          .every((artifactId) => activeArtifactIds.has(artifactId)),
      'Persisted test and cell artifact references resolve to retained script assessments.'
    );
    assert(
      javascriptStartupTest.cells.some(
        (cell) =>
          cell.testId === 'interactive-workflows' &&
          cell.status === 'manual-required' &&
          /does not click controls, submit forms, replay transactions/i.test(cell.detail)
      ),
      'The startup observation preserves its explicit no-interaction boundary.'
    );

    const reportResult = await exerciseTearSheetReport(bridgePassive, { download: true });
    const javascriptReport = reportResult?.payload;
    const reportedScriptAssessments =
      javascriptReport?.correlatedEvidence?.latentFeatureScan?.scriptAssessments ?? [];
    const reportedJavascriptTest = javascriptReport?.correlatedEvidence?.javascriptTest;
    assert(
      reportedScriptAssessments.some(
        (assessment) => assessment.artifact?.artifactId === activeAppAssessment.artifact.artifactId
      ) &&
        reportedJavascriptTest?.testRunId === javascriptStartupTest.testRunId &&
        reportedJavascriptTest.instrumentationIntegrity === 'page-world-unverified',
      'The report correlates the retained /app.js assessment and startup-observation run.'
    );
    assert(
      javascriptReport?.observations?.some(
        (observation) => observation.id === 'correlated-javascript-purpose'
      ) &&
        javascriptReport.observations.some(
          (observation) => observation.id === 'correlated-javascript-startup-observation'
        ) &&
        javascriptReport.limitations?.some(
          (limitation) => limitation.code === 'JAVASCRIPT_PURPOSE_HEURISTIC'
        ) &&
        javascriptReport.limitations.some(
          (limitation) => limitation.code === 'JAVASCRIPT_STARTUP_PATH_ONLY'
        ),
      'The stakeholder report includes JavaScript assessment context and bounded-startup limitations.'
    );

    const originalFeatureContainer = await executeInTarget(
      targetTab.id,
      () => localStorage.getItem('blanche-feature-flags'),
      [],
      'feature-switchboard original storage baseline'
    );
    assert(originalFeatureContainer, 'The local fixture exposes its feature-flag container.');
    await executeInTarget(
      targetTab.id,
      () => {
        const flags = JSON.parse(localStorage.getItem('blanche-feature-flags') ?? '{}');
        flags.latePreviewFeature = false;
        localStorage.setItem('blanche-feature-flags', JSON.stringify(flags));
      },
      [],
      'feature-switchboard late feature injection'
    );
    const switchboardBaseline = await executeInTarget(
      targetTab.id,
      () => localStorage.getItem('blanche-feature-flags'),
      [],
      'feature-switchboard reversible storage baseline'
    );
    clickButton('[data-primary-view="home"]');
    const lateDiscovery = await runAction('latent-features', 'discover', targetTab.id);
    assert(
      ['ok', 'partial'].includes(lateDiscovery.status),
      'Feature Switchboard rescans after a new stored feature appears.'
    );
    const switchboardDiscoveryState = await getState();
    const switchboardScan = switchboardDiscoveryState.latentFeatureWorkbench?.lastScan;
    const lateCandidate = switchboardScan?.candidates.find(
      (candidate) => candidate.key === 'latePreviewFeature'
    );
    assert(
      lateCandidate && switchboardScan.newCandidateIds.includes(lateCandidate.id),
      'The rescan marks the newly added feature candidate as new.'
    );
    assert(
      !switchboardScan.newCandidateIds.some((candidateId) =>
        switchboardScan.candidates.some(
          (candidate) => candidate.id === candidateId && candidate.key === 'compactDashboard'
        )
      ),
      'The rescan does not relabel an existing feature as new.'
    );
    await refreshConsole();
    clickButton('[data-primary-view="labs"]');
    const lateFeatureControl = document.querySelector(
      `[data-latent-state-candidate-id="${lateCandidate.id}"]`
    );
    const lateFeatureCard = lateFeatureControl?.closest('.latent-switch-card');
    assert(
      lateFeatureCard?.classList.contains('is-newly-discovered') &&
        lateFeatureCard.querySelector('.latent-new-badge')?.textContent?.trim() === 'New',
      'The Labs panel flashes and badges the newly discovered feature when it is first shown.'
    );
    assert(
      lateFeatureCard?.querySelector('[data-latent-candidate-state="enabled"]') &&
        lateFeatureCard.querySelector('[data-latent-candidate-state="disabled"]'),
      'The newly discovered feature renders explicit ON and OFF controls.'
    );

    const switchboardCandidates = switchboardScan.candidates;
    const localLatentCandidate = switchboardCandidates.find(
      (candidate) => candidate.key === 'compactDashboard' && candidate.probeable
    );
    const secondLocalCandidate = switchboardCandidates.find(
      (candidate) => candidate.key === 'hiddenTelemetryPanel' && candidate.probeable
    );
    assert(
      localLatentCandidate &&
        localLatentCandidate.enabledValue === true &&
        localLatentCandidate.disabledValue === false,
      'Feature Switchboard derives an explicit reversible ON/OFF pair for the local flag.'
    );
    assert(secondLocalCandidate, 'Feature Switchboard finds a second reversible local flag.');

    const secondLatentEnable = await runAction(
      'latent-features',
      'setCandidateState',
      targetTab.id,
      {
        candidateId: secondLocalCandidate.id,
        state: 'enabled'
      }
    );
    assert(
      ['ok', 'partial'].includes(secondLatentEnable.status),
      'Feature Switchboard supports a second active flag change before restore.'
    );
    await waitForTargetReady(targetTab.id);
    await refreshConsole();
    clickButton('[data-primary-view="labs"]');

    const mutationIdBeforeEnable = switchboardDiscoveryState.latentFeatureWorkbench?.lastMutation?.mutationId;
    clickButton(
      `[data-latent-state-candidate-id="${localLatentCandidate.id}"][data-latent-candidate-state="enabled"]`
    );
    const latentEnable = await waitFor(
      async () => {
        const state = await getState();
        const mutation = state.latentFeatureWorkbench?.lastMutation;
        if (
          mutation?.mutationId !== mutationIdBeforeEnable &&
          mutation?.candidateId === localLatentCandidate.id &&
          mutation?.requestedState === 'enabled'
        ) {
          return {
            status: mutation.outcome === 'applied' ? 'ok' : 'partial'
          };
        }
        return undefined;
      },
      30000,
      100,
      'the Feature Switchboard ON click to finish'
    );
    assert(
      ['ok', 'partial'].includes(latentEnable.status),
      'Feature Switchboard applies the selected local flag ON state.'
    );
    await waitForTargetReady(targetTab.id);
    const enabledLocalObservation = await executeInTarget(
      targetTab.id,
      () => ({
        value: JSON.parse(localStorage.getItem('blanche-feature-flags') ?? '{}').compactDashboard,
        panelPresent: Boolean(document.querySelector('#compact-dashboard-panel')),
        panelHighlighted:
          document.querySelector('#compact-dashboard-panel')?.getAttribute(
            'data-blanche-latent-highlight'
          ) === 'added'
      }),
      [],
      'feature-switchboard ON verification'
    );
    const enabledSwitchboardState = await getState();
    const enabledMutation = enabledSwitchboardState.latentFeatureWorkbench?.lastMutation;
    assert(
      enabledLocalObservation.value === true && enabledLocalObservation.panelPresent,
      'The ON state changes storage and reveals the fixture feature on the page.'
    );
    assert(
      enabledMutation?.candidateId === localLatentCandidate.id &&
        enabledMutation.requestedState === 'enabled' &&
        enabledMutation.previousValue === false &&
        enabledMutation.appliedValue === true &&
        enabledMutation.codeDiff.before.includes('false') &&
        enabledMutation.codeDiff.after.includes('true') &&
        enabledMutation.pageDiff.added.some((entry) => entry.tagName === 'section') &&
        enabledMutation.pageDiff.highlightedCount > 0 &&
        enabledLocalObservation.panelHighlighted,
      'The ON mutation records a virtual code diff, an observed page addition, and a live page highlight.'
    );
    await refreshConsole();
    clickButton('[data-primary-view="labs"]');
    assert(
      document.querySelector('.latent-mutation-evidence .latent-code-diff del')?.textContent?.includes(
        'false'
      ) &&
        document.querySelector('.latent-mutation-evidence .latent-code-diff ins')?.textContent?.includes(
          'true'
        ) &&
        /Observed after toggle/i.test(
          document.querySelector('.latent-page-diff-heading')?.textContent ?? ''
        ),
      'The panel renders highlighted before/after code and clearly labels the DOM comparison as observational.'
    );

    clickButton(
      `[data-latent-state-candidate-id="${localLatentCandidate.id}"][data-latent-candidate-state="disabled"]`
    );
    const latentDisable = await waitFor(
      async () => {
        const state = await getState();
        const mutation = state.latentFeatureWorkbench?.lastMutation;
        if (
          mutation?.candidateId === localLatentCandidate.id &&
          mutation?.requestedState === 'disabled' &&
          mutation?.mutationId !== enabledMutation?.mutationId
        ) {
          return {
            status: mutation.outcome === 'applied' ? 'ok' : 'partial'
          };
        }
        return undefined;
      },
      30000,
      100,
      'the Feature Switchboard OFF click to finish'
    );
    assert(
      ['ok', 'partial'].includes(latentDisable.status),
      'Feature Switchboard applies OFF while retaining the original recovery baseline.'
    );
    await waitForTargetReady(targetTab.id);
    const disabledLocalObservation = await executeInTarget(
      targetTab.id,
      () => ({
        value: JSON.parse(localStorage.getItem('blanche-feature-flags') ?? '{}').compactDashboard,
        panelPresent: Boolean(document.querySelector('#compact-dashboard-panel')),
        removedParentHighlighted:
          document.body.getAttribute('data-blanche-latent-highlight') === 'removed'
      }),
      [],
      'feature-switchboard OFF verification'
    );
    const disabledSwitchboardState = await getState();
    const disabledMutation = disabledSwitchboardState.latentFeatureWorkbench?.lastMutation;
    assert(
      disabledLocalObservation.value === false && !disabledLocalObservation.panelPresent,
      'The OFF state changes storage and hides the fixture feature on the page.'
    );
    assert(
      disabledMutation?.requestedState === 'disabled' &&
        disabledMutation.previousValue === true &&
        disabledMutation.appliedValue === false &&
        disabledMutation.pageDiff.removed.some((entry) => entry.tagName === 'section') &&
        disabledMutation.pageDiff.highlightedCount > 0 &&
        disabledLocalObservation.removedParentHighlighted,
      'The OFF mutation records and highlights the observed page removal.'
    );

    const multiToggleState = await getState();
    assert(
      multiToggleState.latentFeatureWorkbench?.activeProbe?.changes.length === 2,
      'One recovery record retains both active feature changes.'
    );

    const latentRestore = await runAction('latent-features', 'restoreProbe', targetTab.id);
    assert(
      ['ok', 'partial'].includes(latentRestore.status),
      'Feature Switchboard restores every active local flag change.'
    );
    await waitForTargetReady(targetTab.id);
    const restoredFeatureContainer = await executeInTarget(
      targetTab.id,
      () => localStorage.getItem('blanche-feature-flags'),
      [],
      'feature-switchboard exact restore verification'
    );
    const restoredFlags = JSON.parse(restoredFeatureContainer ?? '{}');
    assert(
      restoredFeatureContainer === switchboardBaseline &&
        restoredFlags.compactDashboard === false &&
        restoredFlags.hiddenTelemetryPanel === false,
      'Restore All returns the shared JSON storage container to its exact pre-toggle baseline.'
    );
    await executeInTarget(
      targetTab.id,
      (baseline) => localStorage.setItem('blanche-feature-flags', baseline),
      [originalFeatureContainer],
      'feature-switchboard fixture cleanup'
    );

    const documentFolderRoot = `BLANCHE-smoke-${Date.now()}`;
    await updateModuleSettings('document-acquisition', {
      autoCaptureBrowsedDocuments: true,
      autoDownloadDocuments: false,
      autoDownloadScoreThreshold: 1,
      downloadRuleKeywords: 'secret, token, credential, internal, admin',
      maxDocumentBytes: 1048576,
      downloadFolderRoot: documentFolderRoot,
      interestingKeywords: 'secret, token, credential, internal, admin'
    });
    await refreshConsole();
    clickButton('[data-primary-view="documents"]');
    clickButton('[data-doc-tab="configure"]');
    await waitFor(
      () => document.querySelector('[data-document-setting-key="downloadFolderRoot"]'),
      10000,
      100,
      'Document Center Configure tab to render acquisition settings'
    );
    dispatchInput(document.querySelector('[data-document-setting-key="downloadFolderRoot"]'), documentFolderRoot);
    clickButton('[data-document-settings-action="save"]');
    await waitFor(
      async () => {
        const state = await getState();
        const documentModule = state.modules.find((module) => module.descriptor.id === 'document-acquisition');
        return documentModule?.settings?.downloadFolderRoot === documentFolderRoot;
      },
      10000,
      100,
      'Document Center Configure tab to save acquisition settings'
    );
    clickButton('[data-doc-tab="overview"]');
    const documentSession = await runAction('document-acquisition', 'startSession', undefined, {
      label: 'Smoke Document Session'
    });
    assert(documentSession.status === 'ok', 'Document session starts.');

    await executeInTarget(targetTab.id, async () => {
      const response = await fetch('/docs/auto-capture.csv', {
        cache: 'no-store'
      });
      await response.text();
      return true;
    }, [], 'automatic document capture');

    const autoCapturedDocument = await waitFor(async () => {
      const state = await getState();
      const document = state.documentWorkbench.documents.find(
        (entry) =>
          entry.source === 'web-request' &&
          new URL(entry.url).pathname === '/docs/auto-capture.csv'
      );
      return document &&
        ['acquired', 'reviewed'].includes(document.status) &&
        (document.analysis?.interestingKeywords?.length ?? 0) > 0
        ? document
        : undefined;
    }, 25000, 250, 'the scoped CSV to auto-acquire and complete in-memory analysis');
    assert(
      autoCapturedDocument.source === 'web-request' &&
        (autoCapturedDocument.analysis?.interestingKeywords?.length ?? 0) > 0,
      'The scoped CSV auto-acquired and was analyzed before the explicit page-link scan.'
    );

    const documentScan = await runAction('document-acquisition', 'scanCurrentPageLinks', targetTab.id);
    assert(documentScan.status === 'ok', 'Document link scan completes.');
    const documentState = await waitFor(async () => {
      const state = await getState();
      const documents = state.documentWorkbench.documents;
      const acquired = documents.filter((document) => ['acquired', 'reviewed', 'downloaded'].includes(document.status));
      return documents.length >= 3 && acquired.length >= 2
        ? state.documentWorkbench
        : undefined;
    }, 25000, 250, 'document acquisition and analysis');
    const documentSearchTabsBefore = await chrome.tabs.query({});
    const indexedSearches = await runAction('document-acquisition', 'launchDocumentSearches', targetTab.id, {
      target: 'example.com'
    });
    assert(indexedSearches.data?.searchCount === 7, 'Indexed document searches report seven Google queries.');
    const documentSearchTabs = await waitFor(async () => {
      const beforeIds = new Set(documentSearchTabsBefore.map((tab) => tab.id));
      const currentTabs = await chrome.tabs.query({});
      const createdTabs = currentTabs.filter((tab) => !beforeIds.has(tab.id));
      const matchingTabs = createdTabs.filter((tab) => /^https:\/\/www\.google\.com\/search/i.test(tab.url ?? ''));
      return matchingTabs.length >= 7 ? matchingTabs : undefined;
    }, 15000, 250, 'indexed document search tabs');
    await closeTabs(documentSearchTabs);

    await toggleModule('osint-seed', false);
    const disabledOsintSeed = await runAction('osint-seed', 'seedTarget', targetTab.id);
    assert(disabledOsintSeed.status === 'error', 'Disabled OSINT module rejects actions.');
    await toggleModule('osint-seed', true);
    await updateModuleSettings('osint-seed', {
      autoSendToBurp: true,
      burpSeedUrl: input.osintSeedUrl,
      relatedHostLimit: 20
    });
    const osintSeed = await runAction('osint-seed', 'seedTarget', targetTab.id);
    assert(['ok', 'partial'].includes(osintSeed.status), 'OSINT seed action returns a handled status.');
    assert(osintSeed.data?.relatedHostCount >= 3, 'OSINT seed includes related hosts from page signals.');

    const interestFolderName = `BLANCHE Smoke Interest ${Date.now()}`;
    const interestBaseState = await getState();
    await updateInterestWorkbench({
      ...interestBaseState.interestWorkbench,
      settings: {
        folderName: interestFolderName,
        walkDepth: 3,
        walkCount: 32,
        maxPredictions: 5
      }
    });
    let interestState = await runInterestAction('create-folder', targetTab.id);
    const interestFolderId = interestState.interestWorkbench.settings.folderId;
    assert(interestFolderId, 'Interest folder was created or bound.');
    for (const bookmark of [
      ['Smoke login portal', 'https://login.example.test/sign-in'],
      ['Smoke document vault', 'https://docs.example.test/reports/confidential'],
      ['Smoke admin portal', 'https://portal.example.test/admin']
    ]) {
      await chrome.bookmarks.create({
        parentId: interestFolderId,
        title: bookmark[0],
        url: bookmark[1]
      });
    }
    interestState = await runInterestAction('bookmark-tab', targetTab.id);
    interestState = await runInterestAction('analyze', targetTab.id);
    const interestAnalysis = interestState.interestWorkbench.lastAnalysis;
    assert(interestAnalysis?.bookmarkCount >= 4, 'Interest model learned from bookmark samples.');
    assert(interestAnalysis?.currentTab, 'Interest model scored the current tab.');

    const documentClear = await runAction('document-acquisition', 'clearDocuments');
    assert(documentClear.status === 'ok', 'Document inventory clears.');
    await refreshConsole();
    await sleep(250);
    clickButton('[data-primary-view="traffic"]');
    const trafficView = await waitFor(() => {
      const root = document.querySelector('.traffic-ledger');
      const summaryCardCount = root?.querySelectorAll('.traffic-summary-grid .panelish').length ?? 0;
      const rowCount = root?.querySelectorAll('.traffic-table tbody tr').length ?? 0;
      return root && summaryCardCount >= 4 && rowCount > 0
        ? { summaryCardCount, rowCount }
        : undefined;
    }, 10000, 100, 'the Traffic Ledger summary and endpoint rows to render');
    document.querySelector('.traffic-ledger')?.scrollIntoView({ block: 'start' });

    return {
      initialModuleIds: [...moduleIds],
      targetUrlControls,
      scope: scopeGateVerification,
      trafficView,
      search: {
        builtInProfileCount: builtInProfileIds.length,
        freshDefaultEngineIds: initialState.searchWorkbench.draft.selectedEngineIds,
        operatorCatalogRowCount: operatorCatalog.rowCount,
        searchTabCount: trackedSearch.tasks.length,
        searchUrls: trackedSearch.tasks.map((task) => task.searchUrl),
        dorkSuite: {
          taskCount: dorkSuite.tasks.length,
          mode: dorkSuite.mode,
          previewQuery: dorkPreview.entries[0]?.query,
          previewEntries: dorkPreview.entries,
          dialects: dorkDialects,
          engineOutputs: dorkSuite.tasks.map((task) => ({
            engineId: task.engineId,
            dialect: task.dialect,
            query: task.query,
            operatorIds: task.operatorIds,
            warnings: task.warnings
          })),
          catalogReviewedAt: dorkSuite.catalogReviewedAt
        },
        nerdSuite: {
          taskCount: nerdGetSuite.tasks.length,
          mode: nerdGetSuite.mode,
          surfaceMode: nerdGetTask.nerdSurface?.mode,
          surfaceMethod: nerdGetTask.nerdSurface?.method,
          exactQuery: nerdGetTask.query,
          queries: nerdGetSuite.tasks.map((task) => task.query),
          resultCount: nerdGetSuite.tasks.reduce((total, task) => total + task.resultCount, 0),
          resultUrls: nerdGetSuite.tasks.flatMap((task) =>
            task.results.map((result) => result.url)
          ),
          portablePreview: portablePreview.entries,
          keywordPassCounts: {
            acquisitionProject: portablePreview.firstTermCount,
            legacyPortal: portablePreview.secondTermCount
          },
          roundRobinTerms: portablePreview.roundRobinTerms,
          surfaceHostBound: nerdGetSuite.tasks.every(
            (task) =>
              task.target === new URL(input.testOrigin).hostname &&
              JSON.stringify(task.targets) ===
                JSON.stringify([new URL(input.testOrigin).hostname])
          ),
          candidateHighlightVerified:
            highlightObservation.highlighted &&
            highlightObservation.url === targetUrlBeforeSelectorChecks,
          topFramePickerVerified:
            pickerClickObservation.clicked &&
            targetUrlAfterPicker === targetUrlBeforeSelectorChecks &&
            pickerMarkerRemaining === false,
          fingerprintRendered: /Observed behavior fingerprint/i.test(siteSearchFingerprint.text) &&
            /results observed/i.test(siteSearchFingerprint.text)
        },
        nerdPostSuite: {
          taskCount: nerdPostSuite.tasks.length,
          mode: nerdPostSuite.mode,
          surfaceMode: nerdPostTask.nerdSurface?.mode,
          surfaceMethod: nerdPostTask.nerdSurface?.method,
          exactQuery: nerdPostTask.query,
          discoveredSafeFixedParams: savedPostNerdSurface.fixedParams,
          resultCount: nerdPostTask.resultCount,
          resultUrls: nerdPostTask.results.map((result) => result.url)
        },
        nerdDynamicSuite: {
          taskCount: nerdDynamicSuite.tasks.length,
          mode: nerdDynamicSuite.mode,
          surfaceMode: nerdDynamicTask.nerdSurface?.mode,
          surfaceMethod: nerdDynamicTask.nerdSurface?.method,
          exactQuery: nerdDynamicTask.query,
          resultCount: nerdDynamicTask.resultCount,
          resultUrls: nerdDynamicTask.results.map((result) => result.url)
        },
        nerdTemplateSuite: {
          taskCount: nerdTemplateSuite.tasks.length,
          mode: nerdTemplateSuite.mode,
          surfaceMode: nerdTemplateTask.nerdSurface?.mode,
          surfaceMethod: nerdTemplateTask.nerdSurface?.method,
          exactQuery: nerdTemplateTask.query,
          searchUrl: nerdTemplateTask.searchUrl,
          resultCount: nerdTemplateTask.resultCount,
          resultUrls: nerdTemplateTask.results.map((result) => result.url)
        },
        yandexOrBaiduPresent: /Yandex|Baidu/i.test(document.body.innerText)
      },
      bridgeCollect,
      bridgePassive,
      report: reportResult,
      latentFeatures: {
        discovery: latentDiscovery,
        candidateCount: latentCandidates.length,
        runtimeCandidatePresent: latentCandidates.some(
          (candidate) => candidate.key === 'remotePreviewPanel'
        ),
        localCandidatePresent: Boolean(localLatentCandidate),
        lateDiscoveryStatus: lateDiscovery.status,
        newFeatureFlashVerified:
          lateFeatureCard?.classList.contains('is-newly-discovered') === true &&
          lateFeatureCard.querySelector('.latent-new-badge')?.textContent?.trim() === 'New',
        onOffControlsPresent: Boolean(
          lateFeatureCard?.querySelector('[data-latent-candidate-state="enabled"]') &&
            lateFeatureCard.querySelector('[data-latent-candidate-state="disabled"]')
        ),
        enabledLocalValue: enabledLocalObservation.value,
        enabledPanelPresent: enabledLocalObservation.panelPresent,
        enabledPanelHighlighted: enabledLocalObservation.panelHighlighted,
        disabledLocalValue: disabledLocalObservation.value,
        disabledPanelPresent: disabledLocalObservation.panelPresent,
        disabledPanelRemovalHighlighted: disabledLocalObservation.removedParentHighlighted,
        enableStatus: latentEnable.status,
        disableStatus: latentDisable.status,
        secondEnableStatus: secondLatentEnable.status,
        restoreStatus: latentRestore.status,
        exactContainerRestore: restoredFeatureContainer === switchboardBaseline,
        activeChangeCountBeforeRestore:
          multiToggleState.latentFeatureWorkbench?.activeProbe?.changes.length ?? 0,
        codeDiffVerified:
          enabledMutation?.codeDiff.before.includes('false') === true &&
          enabledMutation?.codeDiff.after.includes('true') === true,
        pageAdditionVerified:
          enabledMutation?.pageDiff.added.some((entry) => entry.tagName === 'section') === true &&
          enabledMutation.pageDiff.highlightedCount > 0,
        pageRemovalVerified:
          disabledMutation?.pageDiff.removed.some((entry) => entry.tagName === 'section') === true &&
          disabledMutation.pageDiff.highlightedCount > 0,
        javascriptAnalysis: {
          rawDocumentAssessmentPresent:
            rawJavascriptAssessment?.artifact?.sourceKind === 'document',
          queuedPassiveStartupSerialized:
            queuedDiscoveryLoadCountAfter === queuedDiscoveryLoadCountBefore + 1 &&
            queuedDiscoveryState.latentFeatureWorkbench?.lastJavascriptTest?.testRunId ===
              queuedStartupObservation.data.javascriptTestRunId,
          multiCandidateRecoveryRetained:
            multiToggleState.latentFeatureWorkbench?.activeProbe?.changes.length === 2,
          passiveAssessmentCount: passiveScriptAssessments.length,
          passiveAppAssessmentPresent: Boolean(passiveAppAssessment),
          passiveReloadCountDelta: passiveLoadCountAfter.count - passiveLoadCountBefore.count,
          startupActionStatus: javascriptStartupAction.status,
          startupTestRunId: javascriptStartupTest.testRunId,
          startupReloadCountDelta: startupLoadCountAfter.count - startupLoadCountBefore.count,
          startupScopeDisposition: javascriptStartupTest.scopeDisposition,
          startupInstrumentationAvailable: javascriptStartupTest.instrumentationAvailable,
          startupInstrumentationIntegrity: javascriptStartupTest.instrumentationIntegrity,
          sourceBindingMatches:
            javascriptStartupTest.scanId ===
              javascriptState.latentFeatureWorkbench?.lastScan?.scanId &&
            javascriptStartupTest.artifactFingerprints.length === activeScriptAssessments.length,
          evidenceRecordCount: javascriptStartupTest.evidence.length,
          allCellEvidenceRefsResolve: javascriptStartupTest.cells
            .flatMap((cell) => cell.evidenceRefs ?? [])
            .every((evidenceId) => retainedTestEvidenceIds.has(evidenceId)),
          runtimeStats: javascriptStartupTest.runtimeStats,
          observedCellIds: javascriptStartupTest.cells
            .filter((cell) => cell.status === 'observed')
            .map((cell) => cell.testId),
          unverifiedObservedCellIds: javascriptStartupTest.cells
            .filter((cell) => cell.status === 'observed-unverified')
            .map((cell) => cell.testId),
          reportScriptAssessmentCount: reportedScriptAssessments.length,
          reportJavascriptTestRunId: reportedJavascriptTest?.testRunId,
          reportHasJavascriptContext:
            javascriptReport?.observations?.some(
              (observation) => observation.id === 'correlated-javascript-purpose'
            ) === true &&
            javascriptReport?.observations?.some(
              (observation) => observation.id === 'correlated-javascript-startup-observation'
            ) === true
        }
      },
      documents: {
        session: documentSession,
        scan: documentScan,
        documentCount: documentState.documents.length,
        acquiredDocumentCount: documentState.documents.filter((document) => ['acquired', 'reviewed', 'downloaded'].includes(document.status)).length,
        interestingDocumentCount: documentState.documents.filter((document) =>
          (document.analysis?.interestingKeywords?.length ?? 0) > 0 ||
          (document.analysis?.extractedUrls?.length ?? 0) > 0
        ).length,
        indexedSearchCount: indexedSearches.data?.searchCount ?? 0,
        autoCapturedDocumentStatus: autoCapturedDocument.status,
        autoCapturedDocumentKeywordCount:
          autoCapturedDocument.analysis?.interestingKeywords?.length ?? 0,
        downloadFolderRoot: documentFolderRoot,
        clearStatus: documentClear.status
      },
      disabledOsintSeed,
      osintSeed,
      interest: {
        bookmarkCount: interestAnalysis.bookmarkCount,
        topSignalCount: interestAnalysis.topSignals.length,
        predictionCount: interestAnalysis.currentTab?.predictions.length ?? 0,
        folderStatus: interestAnalysis.folderStatus
      }
    };
  }.toString()})(${JSON.stringify({
    testOrigin,
    reviewScopeOrigin,
    ingestUrl,
    osintSeedUrl,
    tearSheetOnly,
    targetUrlControlsOnly,
    siteSearchOnly
  })})`;
}

function verifySiteSearchOnlyResult(workflowResult) {
  const suite = workflowResult.search?.nerdSuite;
  assert(
    JSON.stringify(workflowResult.search?.freshDefaultEngineIds) === JSON.stringify(['google']),
    'A fresh Search Workbench uses Google as its sole selected default engine.'
  );
  assert(
    suite?.taskCount === 4 &&
      suite.mode === 'nerd' &&
      suite.surfaceMode === 'get' &&
      suite.surfaceMethod === 'get' &&
      suite.resultCount >= 4 &&
      suite.resultUrls?.some((url) => url.includes('/docs/readme.txt')) &&
      suite.portablePreview?.length === 4 &&
      suite.portablePreview.every((entry) => !/\bsite:/i.test(entry.query ?? '')) &&
      suite.keywordPassCounts?.acquisitionProject === 2 &&
      suite.keywordPassCounts?.legacyPortal === 2 &&
      JSON.stringify(suite.roundRobinTerms) ===
        JSON.stringify([
          'acquisition project',
          'legacy portal',
          'acquisition project',
          'legacy portal'
        ]) &&
      suite.surfaceHostBound === true &&
      suite.candidateHighlightVerified === true &&
      suite.topFramePickerVerified === true &&
      suite.fingerprintRendered === true,
    'The focused Site Search selector, host binding, multi-term plan, result parsing, and behavior fingerprint pass.'
  );
}

async function evaluateJson(client, expression) {
  const response = await client.send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
    timeout: 60000
  });

  if (response.exceptionDetails) {
    throw new Error(
      response.exceptionDetails.exception?.description ??
        response.exceptionDetails.text ??
        'Runtime evaluation failed.'
    );
  }

  return response.result.value;
}

async function captureWorkflowScreenshot(
  client,
  filename = 'chromium-extension-workflow-smoke.png'
) {
  await fs.mkdir(workSummaryDir, { recursive: true });
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 1200,
    deviceScaleFactor: 1,
    mobile: false
  });
  await client.send('Runtime.evaluate', {
    expression: 'window.scrollTo(0, 0)',
    awaitPromise: false
  });
  const screenshot = await client.send('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: true,
    fromSurface: true
  });
  const screenshotPath = path.join(workSummaryDir, filename);
  await fs.writeFile(screenshotPath, Buffer.from(screenshot.data, 'base64'));
  return screenshotPath;
}

async function captureNarrowTargetUrlControlsScreenshot(client) {
  await fs.mkdir(workSummaryDir, { recursive: true });
  const readNarrowLayout = () =>
    evaluateJson(
      client,
      `(() => {
        window.scrollTo(0, 0);
        const strip = document.querySelector('.target-strip');
        const disclosure = document.querySelector('.target-url-disclosure');
        const copyButtons = [...document.querySelectorAll('[data-target-copy]')];
        const primaryNav = document.querySelector('.primary-nav');
        const navButtons = [...document.querySelectorAll('.primary-nav [data-primary-view]')];
        const outputSelector = document.querySelector('[data-target-output-select]');
        const outputSelectorGroup = document.querySelector('.target-output-selector');
        if (
          !strip ||
          !(disclosure instanceof HTMLDetailsElement) ||
          copyButtons.length !== 4 ||
          !primaryNav ||
          navButtons.length !== 7 ||
          !(outputSelector instanceof HTMLSelectElement) ||
          outputSelector.options.length !== 4 ||
          !outputSelectorGroup
        ) {
          return { ready: false };
        }
        const fitsHorizontally = (element) => {
          const bounds = element.getBoundingClientRect();
          return bounds.left >= -1 && bounds.right <= window.innerWidth + 1;
        };
        return {
          ready: true,
          collapsed: disclosure.open === false,
          documentFits: document.documentElement.scrollWidth <= window.innerWidth + 1,
          stripFits: strip.scrollWidth <= strip.clientWidth + 1,
          primaryNavFits:
            primaryNav.scrollWidth <= primaryNav.clientWidth + 1 &&
            fitsHorizontally(primaryNav),
          navButtonCount: navButtons.length,
          navButtonsFit: navButtons.every(fitsHorizontally),
          targetSelectorFits:
            outputSelectorGroup.scrollWidth <= outputSelectorGroup.clientWidth + 1 &&
            fitsHorizontally(outputSelectorGroup) &&
            fitsHorizontally(outputSelector) &&
            copyButtons.every(fitsHorizontally)
        };
      })()`
    );
  const assertNarrowLayout = (layout, width) =>
    assert(
      layout?.ready === true &&
        layout?.collapsed === true &&
        layout?.documentFits === true &&
        layout?.stripFits === true &&
        layout?.primaryNavFits === true &&
        layout?.navButtonCount === 7 &&
        layout?.navButtonsFit === true &&
        layout?.targetSelectorFits === true,
      `Target/output controls and all seven navigation buttons fit a ${width}px-wide side panel without horizontal document or navigation overflow. Observed: ${JSON.stringify(layout)}`
    );
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 420,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false
  });
  assertNarrowLayout(await readNarrowLayout(), 420);
  const screenshot = await client.send('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: true,
    fromSurface: true
  });
  const screenshotPath = path.join(workSummaryDir, 'target-url-controls-narrow-smoke.png');
  await fs.writeFile(screenshotPath, Buffer.from(screenshot.data, 'base64'));
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 360,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false
  });
  assertNarrowLayout(await readNarrowLayout(), 360);
  return screenshotPath;
}

async function verifyNarrowTrafficTableLayout(client) {
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 360,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false
  });
  await evaluateJson(
    client,
    `(() => {
      const trafficButton = document.querySelector('[data-primary-view="traffic"]');
      if (!(trafficButton instanceof HTMLButtonElement)) return false;
      trafficButton.click();
      return true;
    })()`
  );
  await waitFor(
    () =>
      evaluateJson(
        client,
        `Boolean(document.querySelector('.traffic-table tbody tr'))`
      ),
    10000,
    100,
    'the Traffic table to render for the narrow layout check'
  );
  const layout = await evaluateJson(
    client,
    `(() => {
      window.scrollTo(0, 0);
      const table = document.querySelector('.traffic-table');
      const rows = [...document.querySelectorAll('.traffic-table tbody tr')];
      const cells = [...document.querySelectorAll('.traffic-table tbody td')];
      if (!table || rows.length === 0 || cells.length === 0) return { ready: false };
      const fitsHorizontally = (element) => {
        const bounds = element.getBoundingClientRect();
        return bounds.left >= -1 && bounds.right <= window.innerWidth + 1;
      };
      return {
        ready: true,
        documentFits: document.documentElement.scrollWidth <= window.innerWidth + 1,
        stacked: getComputedStyle(table).display === 'block',
        rowsFit: rows.every(fitsHorizontally),
        cellsFit: cells.every(fitsHorizontally),
        cellsUseRowWidth: cells.every((cell) => {
          const cellBounds = cell.getBoundingClientRect();
          const rowBounds = cell.closest('tr')?.getBoundingClientRect();
          return rowBounds && Math.abs(cellBounds.width - rowBounds.width) <= 2;
        })
      };
    })()`
  );
  assert(
    layout?.ready === true &&
      layout?.documentFits === true &&
      layout?.stacked === true &&
      layout?.rowsFit === true &&
      layout?.cellsFit === true &&
      layout?.cellsUseRowWidth === true,
    `Traffic rows stack at 360px without clipped fixed-width cells or horizontal document overflow. Observed: ${JSON.stringify(layout)}`
  );
}

async function captureJavascriptAnalysisScreenshot(client) {
  await fs.mkdir(workSummaryDir, { recursive: true });
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 1200,
    deviceScaleFactor: 1,
    mobile: false
  });
  await evaluateJson(
    client,
    `(() => {
      const labs = document.querySelector('[data-primary-view="labs"]');
      if (!labs) throw new Error('Labs navigation button is missing.');
      labs.click();
      return true;
    })()`
  );
  await waitFor(
    () =>
      evaluateJson(
        client,
        `(() => {
          const panel = document.querySelector('.latent-feature-workbench');
          const switchboard = panel?.querySelector('.latent-switchboard');
          const codeDiff = panel?.querySelector('.latent-mutation-evidence .latent-code-diff');
          const analysis = panel?.querySelector('.javascript-analysis-results');
          const startup = panel?.querySelector('.javascript-test-results');
          if (!panel || !switchboard || !codeDiff || !analysis || !startup) {
            return false;
          }
          const text = panel.textContent ?? '';
          if (!/Feature switches/i.test(text) || !/Delivered JavaScript/i.test(text) || !/Bounded startup observation/i.test(text)) return false;
          const panelTop = panel.getBoundingClientRect().top + window.scrollY;
          window.scrollTo(0, Math.max(0, panelTop - 64));
          return true;
        })()`
      ),
    10000,
    100,
    'the JavaScript analysis and startup-observation panels to render'
  );
  const resultScreenshot = await client.send('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: false,
    fromSurface: true
  });
  const resultPath = path.join(workSummaryDir, 'feature-switchboard-result-smoke.png');
  await fs.writeFile(resultPath, Buffer.from(resultScreenshot.data, 'base64'));
  await evaluateJson(
    client,
    `(() => {
      const switchboard = document.querySelector('.latent-switchboard');
      if (!switchboard) throw new Error('Feature switches panel is missing.');
      const top = switchboard.getBoundingClientRect().top + window.scrollY;
      window.scrollTo(0, Math.max(0, top - 64));
      return true;
    })()`
  );
  const controlsScreenshot = await client.send('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: false,
    fromSurface: true
  });
  const controlsPath = path.join(workSummaryDir, 'feature-switchboard-controls-smoke.png');
  await fs.writeFile(controlsPath, Buffer.from(controlsScreenshot.data, 'base64'));
  return {
    result: resultPath,
    controls: controlsPath
  };
}

async function captureSearchFeatureScreenshots(client) {
  const captureTab = async (tabId, rootSelector, filename) => {
    await evaluateJson(
      client,
      `(() => {
        const primary = document.querySelector('[data-primary-view="search"]');
        if (!primary) throw new Error('Search primary navigation is missing.');
        primary.click();
        const tab = document.querySelector('[data-search-tab="${tabId}"]');
        if (!tab) throw new Error('Search tab ${tabId} is missing.');
        tab.click();
        return true;
      })()`
    );
    await waitFor(
      () =>
        evaluateJson(
          client,
          `Boolean(document.querySelector('${rootSelector}'))`
        ),
      10000,
      100,
      `the ${tabId} search view to render for screenshot capture`
    );
    return await captureWorkflowScreenshot(client, filename);
  };

  return {
    dorkSuite: await captureTab('suite', '[data-dork-suite]', 'dork-suite-smoke.png'),
    nerdMode: await captureTab('nerd', '[data-nerd-mode]', 'nerd-mode-smoke.png'),
    operatorCatalog: await captureTab(
      'catalog',
      '[data-search-operator-catalog]',
      'search-operator-catalog-smoke.png'
    )
  };
}

async function captureDynamicTearSheetScreenshot(
  client,
  filename = 'site-tear-sheet-smoke.png'
) {
  await evaluateJson(
    client,
    `(() => {
      const reportNavigation = document.querySelector('[data-primary-view="report"]');
      if (!reportNavigation) throw new Error('Report navigation button is missing.');
      reportNavigation.click();
      const button = document.querySelector('[data-report-mode="stakeholder"]');
      if (!button) throw new Error('Stakeholder report mode button is missing.');
      button.click();
      return true;
    })()`
  );
  await waitFor(
    () =>
      evaluateJson(
        client,
        `(() => {
          const root = document.querySelector('[data-tear-sheet-report]');
          return Boolean(root && /limitations/i.test(root.textContent ?? ''));
        })()`
      ),
    10000,
    100,
    'the dynamic stakeholder report to render for screenshot capture'
  );
  return await captureWorkflowScreenshot(client, filename);
}

async function captureTearSheetScreenshot(browserClient, debugPort) {
  const tearSheetPath = path.join(rootDir, 'docs', 'blanche-tear-sheet.html');
  await fs.access(tearSheetPath);
  await fs.mkdir(workSummaryDir, { recursive: true });

  const { targetId } = await browserClient.send('Target.createTarget', {
    url: pathToFileURL(tearSheetPath).toString()
  });
  const tearSheetClient = await connectToTarget(debugPort, targetId);
  try {
    await tearSheetClient.send('Runtime.enable');
    await tearSheetClient.send('Page.enable');
    await tearSheetClient.send('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 1100,
      deviceScaleFactor: 1,
      mobile: false
    });
    await waitFor(
      async () => {
        const state = await evaluateJson(
          tearSheetClient,
          '({ readyState: document.readyState, title: document.title, text: document.body.innerText })'
        );
        return state.readyState === 'complete' ? state : undefined;
      },
      10000,
      100,
      'the BLANCHE tear sheet to render'
    );

    const pageText = await evaluateJson(tearSheetClient, 'document.body.innerText');
    assert(pageText.includes('Search Workbench'), 'Tear sheet describes Search Workbench.');
    assert(pageText.includes('Document Center'), 'Tear sheet describes Document Center.');
    assert(pageText.includes('Burp Bridge'), 'Tear sheet describes Burp Bridge.');
    assert(pageText.includes('Built-In OSINT Profiles'), 'Tear sheet describes built-in profiles.');

    const screenshot = await tearSheetClient.send('Page.captureScreenshot', {
      format: 'png',
      captureBeyondViewport: true,
      fromSurface: true
    });
    const screenshotPath = path.join(workSummaryDir, 'blanche-tear-sheet.png');
    await fs.writeFile(screenshotPath, Buffer.from(screenshot.data, 'base64'));
    return screenshotPath;
  } finally {
    tearSheetClient.close();
  }
}

async function waitForTearSheetDownloads(downloadDir) {
  return await waitFor(
    async () => {
      const entries = await fs.readdir(downloadDir, { withFileTypes: true });
      const fileNames = entries.filter((entry) => entry.isFile()).map((entry) => entry.name);
      if (fileNames.some((name) => name.endsWith('.crdownload'))) {
        return undefined;
      }

      const htmlName = fileNames.find((name) => /^blanche_.+_tear-sheet\.html$/i.test(name));
      const jsonName = fileNames.find((name) => /^blanche_.+_tear-sheet\.json$/i.test(name));
      if (!htmlName || !jsonName) {
        return undefined;
      }

      const [htmlContents, jsonContents] = await Promise.all([
        fs.readFile(path.join(downloadDir, htmlName), 'utf8'),
        fs.readFile(path.join(downloadDir, jsonName), 'utf8')
      ]);
      if (!htmlContents.trim() || !jsonContents.trim()) {
        return undefined;
      }

      try {
        JSON.parse(jsonContents);
      } catch {
        return undefined;
      }

      return {
        html: {
          name: htmlName,
          contents: htmlContents
        },
        json: {
          name: jsonName,
          contents: jsonContents
        }
      };
    },
    15000,
    100,
    'the stakeholder HTML and JSON evidence downloads to complete'
  );
}

function verifyNerdPostSubmission(workflowResult, observed) {
  const expectedQuery = workflowResult.search?.nerdPostSuite?.exactQuery;
  assert(observed?.method === 'POST', 'The disposable search target received a real POST request.');
  assert(observed?.pathname === '/search/post', 'The POST NERD form used its discovered action path.');
  assert(
    observed?.contentType?.startsWith('application/x-www-form-urlencoded'),
    'The POST NERD form used the browser form transport.'
  );
  assert(
    Boolean(expectedQuery) && observed?.query === expectedQuery,
    'The POST NERD form submitted the exact generated query.'
  );
  assert(observed?.corpus === 'knowledge', 'The POST NERD form retained its selected safe field.');
  assert(
    observed?.sensitiveControlSubmitted === true,
    'The browser replayed the live form, including its page-managed hidden control.'
  );
  return {
    method: observed.method,
    pathname: observed.pathname,
    contentType: observed.contentType,
    exactQuery: observed.query,
    corpus: observed.corpus,
    pageManagedSensitiveControlSubmitted: observed.sensitiveControlSubmitted
  };
}

function verifyNerdDynamicSubmission(workflowResult, observed) {
  const expectedQuery = workflowResult.search?.nerdDynamicSuite?.exactQuery;
  assert(observed?.method === 'GET', 'The JavaScript search widget completed a real navigation.');
  assert(
    observed?.pathname === '/search/dynamic',
    'The JavaScript search widget used its runtime-selected action path.'
  );
  assert(
    Boolean(expectedQuery) && observed?.query === expectedQuery,
    'The JavaScript search widget submitted the exact generated query.'
  );
  assert(observed?.view === 'widget', 'The JavaScript search widget retained its runtime route state.');
  return {
    method: observed.method,
    pathname: observed.pathname,
    exactQuery: observed.query,
    view: observed.view
  };
}

function verifySearchFeatureDownloads(workflowResult, downloads) {
  assert(
    workflowResult.report?.downloadsRequested?.html === true &&
      workflowResult.report?.downloadsRequested?.json === true,
    'The full workflow clicked both dynamic report download controls.'
  );
  const report = JSON.parse(downloads.json.contents);
  const nerdTasks = (report.correlatedEvidence?.searchSessions ?? [])
    .filter((session) => session.mode === 'nerd')
    .flatMap((session) => session.tasks ?? []);
  assert(
    nerdTasks.some(
      (task) =>
        task.nerdSurface?.mode === 'get' &&
        task.status === 'completed-results' &&
        task.results?.some((result) => result.url?.includes('/docs/readme.txt'))
    ),
    'Downloaded report JSON preserves the discovered GET NERD output.'
  );
  assert(
    nerdTasks.some(
      (task) =>
        task.nerdSurface?.mode === 'form' &&
        task.nerdSurface?.method === 'post' &&
        task.status === 'completed-results' &&
        task.results?.some((result) => result.url?.includes('from=nerd-post'))
    ),
    'Downloaded report JSON preserves the discovered POST NERD output.'
  );
  assert(
    nerdTasks.some(
      (task) =>
        task.nerdSurface?.mode === 'form' &&
        task.nerdSurface?.method === 'dynamic' &&
        task.status === 'completed-results' &&
        task.results?.some((result) => result.url?.includes('from=nerd-dynamic'))
    ),
    'Downloaded report JSON preserves the JavaScript-driven NERD output.'
  );
  assert(
    nerdTasks.some(
      (task) =>
        task.nerdSurface?.mode === 'template' &&
        task.status === 'completed-results' &&
        task.searchUrl?.includes('section=template')
    ),
    'Downloaded report JSON preserves the reviewed URL-template NERD output.'
  );
  assert(
    downloads.html.contents.includes('NERD GET') &&
      downloads.html.contents.includes('NERD form') &&
      downloads.html.contents.includes('POST') &&
      downloads.html.contents.includes('DYNAMIC') &&
      downloads.html.contents.includes('NERD URL template'),
    'Downloaded stakeholder HTML renders all four NERD surface transports.'
  );
  assert(
    downloads.html.contents.includes('Operator catalog reviewed 2026-09-09'),
    'Downloaded stakeholder HTML preserves the date-only operator catalog review date.'
  );
  assert(
    !downloads.html.contents.includes('must-not-be-reported') &&
      !downloads.json.contents.includes('must-not-be-reported'),
    'Downloaded reports do not expose the page-managed hidden form value.'
  );
}

function verifyTearSheetOnlyResult(workflowResult, testOrigin, downloads) {
  assert(workflowResult?.mode === 'tear-sheet-only', 'Focused workflow returned tear-sheet-only mode.');
  const sourceCapture = workflowResult.bridgePassive?.export;
  assert(sourceCapture?.collection?.mode === 'passive', 'Focused workflow returned a passive source capture.');
  assert(
    workflowResult.bridgePassive?.warnings?.some(
      (warning) => warning.code === 'PASSIVE_MODE_PROVENANCE_LIMIT'
    ),
    'Focused workflow retained its passive provenance warning.'
  );

  const reportResult = workflowResult.report;
  const report = reportResult?.payload;
  const embeddedSourceCapture = report?.sourceCapture;
  const expectedHostname = new URL(testOrigin).hostname;
  assert(report?.kind === 'blanche.tear-sheet', 'Focused report uses the BLANCHE tear sheet kind.');
  assert(report?.schemaVersion === '1.0.0', 'Focused report uses the supported schema version.');
  assert(
    embeddedSourceCapture?.exportMetadata?.exportId === sourceCapture?.exportMetadata?.exportId &&
      report?.metadata?.sourceExportId === embeddedSourceCapture?.exportMetadata?.exportId,
    'Focused report source export IDs match the passive capture.'
  );
  assert(
    embeddedSourceCapture?.summary?.artifactCount === sourceCapture?.summary?.artifactCount &&
      report?.evidenceSummary?.artifactCount === embeddedSourceCapture?.summary?.artifactCount,
    'Focused report artifact counts match the passive capture.'
  );
  assert(report?.target?.hostname === expectedHostname, 'Focused report target matches the local smoke target.');

  const provenance = report?.evidenceSummary?.provenance;
  assert(
    provenance &&
      provenance.observed + provenance.inferred + provenance.unavailable ===
        report.evidenceSummary.artifactCount,
    'Focused report provenance totals account for every artifact.'
  );
  assert(
    Array.isArray(report?.limitations) && report.limitations.length > 0,
    'Focused report includes capture limitations.'
  );
  const expectedBrowserOnlyArtifactCount = Object.values(
    countChromiumOnlyArtifacts(embeddedSourceCapture.artifacts)
  ).reduce((sum, count) => sum + count, 0);
  assert(expectedBrowserOnlyArtifactCount > 0, 'Focused source capture includes browser-only evidence.');
  assert(
    report.evidenceSummary.browserOnlyArtifactCount === expectedBrowserOnlyArtifactCount,
    'Focused report browser-only count matches the source-artifact predicate.'
  );
  assert(
    report.dataHandling?.classification === 'assessment-sensitive' &&
      report.dataHandling?.stakeholderViewRedactsRawValues === true &&
      report.dataHandling?.jsonContainsFullEvidence === true,
    'Focused report declares stakeholder masking and full JSON evidence handling.'
  );
  assert(
    reportResult?.controls &&
      Object.keys(reportResult.controls).length === 7 &&
      Object.values(reportResult.controls).every(Boolean),
    'Focused report exposed stakeholder/JSON modes, downloads, copy, and full JSON controls.'
  );
  assert(
    reportResult?.downloadsRequested?.html === true && reportResult.downloadsRequested?.json === true,
    'Focused report clicked both download controls.'
  );
  assert(
    reportResult?.masking?.sensitiveNotice === true &&
      reportResult.masking?.stakeholderStorageValuesHidden === true &&
      reportResult.masking?.jsonStorageValuesRetained === true,
    'Focused report verified its masking notice and raw-value boundary.'
  );

  const downloadedReport = JSON.parse(downloads.json.contents);
  assert(downloadedReport.kind === 'blanche.tear-sheet', 'Downloaded JSON is a BLANCHE tear sheet.');
  assert(
    downloadedReport.metadata?.sourceExportId === sourceCapture.exportMetadata.exportId &&
      downloadedReport.sourceCapture?.summary?.artifactCount === sourceCapture.summary.artifactCount,
    'Downloaded JSON preserves the passive source identity and artifact count.'
  );
  assert(
    /<!doctype html>/i.test(downloads.html.contents) &&
      downloads.html.contents.includes(expectedHostname) &&
      /limitations/i.test(downloads.html.contents) &&
      /provenance/i.test(downloads.html.contents),
    'Downloaded HTML is a standalone stakeholder report with target and evidence context.'
  );
  assert(
    !downloads.html.contents.includes('local-value') &&
      !downloads.html.contents.includes('session-value') &&
      downloads.json.contents.includes('local-value') &&
      downloads.json.contents.includes('session-value'),
    'Downloaded HTML masks raw storage values while downloaded JSON retains them.'
  );

  return {
    hostname: expectedHostname,
    artifactCount: report.evidenceSummary.artifactCount,
    browserOnlyArtifactCount: report.evidenceSummary.browserOnlyArtifactCount,
    limitationCount: report.limitations.length,
    provenance
  };
}

function verifyReceivedExport(receivedExport, actionResult) {
  assert(receivedExport?.kind === 'blanche.export', 'Loopback received a BLANCHE export payload.');
  assert(receivedExport?.schemaVersion === '1.1.0', 'Export uses the score-aware schema version.');
  assert(receivedExport.collection?.mode === 'instrumented', 'Collection mode is instrumented.');
  assert(actionResult?.data?.burpIngested === true, 'Chromium action reported successful Burp ingest.');
  assert(
    actionResult?.data?.burpIngestUrl?.includes(LOOPBACK_PATH),
    'Chromium action reported the loopback ingest URL.'
  );
  assert(
    actionResult?.data?.burpIngestStatus >= 200 && actionResult?.data?.burpIngestStatus < 300,
    'Chromium action reported a successful Burp ingest HTTP status.'
  );

  if (actionResult?.data?.burpIngestResponse) {
    const ingestResponse = JSON.parse(actionResult.data.burpIngestResponse);
    assert(
      ingestResponse.status === 'ok' || ingestResponse.status === 'accepted',
      'Burp ingest response identified a BLANCHE receiver status.'
    );
    assert(
      (ingestResponse.chromiumOnlyArtifactCount ?? 1) > 0,
      'Burp ingest response reported Chromium-only artifacts when available.'
    );
  }

  const artifacts = Array.isArray(receivedExport.artifacts) ? receivedExport.artifacts : [];
  const trafficLedger = receivedExport.trafficLedger;
  const trafficEntries = Array.isArray(trafficLedger?.entries) ? trafficLedger.entries : [];
  const collectors = Array.isArray(receivedExport.collectors) ? receivedExport.collectors : [];
  const artifactKinds = new Set(artifacts.map((artifact) => artifact.kind));
  const artifactCategories = new Set(artifacts.map((artifact) => artifact.category));
  const collectorStatuses = new Map(
    collectors.map((collector) => [collector.collectorId, collector.status])
  );

  assert(collectorStatuses.get('page-snapshot') !== 'error', 'Page snapshot collector did not error.');
  assert(
    collectorStatuses.get('instrumentation-bridge') !== 'error',
    'Instrumentation bridge collector did not error.'
  );
  assert(artifactCategories.has('storage-key'), 'Export contains local/session storage artifacts.');
  assert(artifactCategories.has('indexeddb-database'), 'Export contains IndexedDB artifacts.');
  assert(artifactCategories.has('cache'), 'Export contains Cache Storage artifacts.');
  assert(artifactCategories.has('service-worker'), 'Export contains service worker artifacts.');
  assert(artifactKinds.has('instrumented-blob-created'), 'Export contains an instrumented blob creation.');
  assert(
    artifacts.some((artifact) => artifact.discoveredBy?.includes('instrumentation')),
    'Export contains artifacts discovered by document_start instrumentation.'
  );
  assert(
    artifacts.some((artifact) => String(artifact.url ?? '').startsWith('data:')),
    'Export contains a data URL artifact.'
  );
  assert(trafficLedger?.kind === 'blanche.traffic-ledger', 'Export embeds the traffic ledger.');
  assert(trafficLedger?.schemaVersion === '1.0.0', 'Traffic ledger uses the supported schema version.');
  assert(trafficEntries.length > 0, 'Traffic ledger contains correlated browser endpoints.');
  assert(
    trafficLedger.summary?.entryCount === trafficEntries.length,
    'Traffic ledger summary matches its entries.'
  );
  const captureCoverage = trafficLedger.metadata?.captureCoverage;
  assert(
    Number.isInteger(captureCoverage?.retainedEntryLimit) &&
      captureCoverage.retainedEntryLimit > 0 &&
      Number.isInteger(captureCoverage?.persistedByteLimit) &&
      captureCoverage.persistedByteLimit > 0 &&
      Number.isInteger(captureCoverage?.droppedEntryCount) &&
      captureCoverage.droppedEntryCount >= 0 &&
      captureCoverage.retentionLossScope === 'store-wide-conservative' &&
      captureCoverage.availableEntryCount >= trafficEntries.length &&
      captureCoverage.exportedEntryCount === trafficEntries.length &&
      typeof captureCoverage.truncated === 'boolean' &&
      Array.isArray(captureCoverage.reasonCodes),
    'Traffic ledger export declares machine-readable retention and truncation coverage.'
  );
  assert(
    trafficEntries.every(
      (entry) =>
        typeof entry.entryId === 'string' &&
        typeof entry.priority?.score === 'number' &&
        entry.priority.score >= 0 &&
        entry.priority.score <= 100 &&
        typeof entry.scope?.policyId === 'string'
    ),
    'Traffic entries retain identity, scope provenance, and bounded priority scores.'
  );
  assert(
    trafficEntries.every(
      (entry) =>
        entry.endpoint?.host !== 'blanche.invalid' &&
        !(entry.endpoint?.host === '127.0.0.1' && entry.endpoint?.pathTemplate?.startsWith('/api/blanche/'))
    ),
    'Traffic ledger excludes BLANCHE control-plane handoffs.'
  );
  const serializedLedger = JSON.stringify(trafficLedger);
  for (const secret of [
    'smoke-secret-token',
    'smoke-query-secret',
    'smoke-header-secret',
    'smoke-body-secret'
  ]) {
    assert(!serializedLedger.includes(secret), `Traffic ledger does not retain ${secret}.`);
  }
  assert(
    trafficLedger.dataHandling?.queryValuesIncluded === false &&
      trafficLedger.dataHandling?.fragmentsIncluded === false &&
      trafficLedger.dataHandling?.userinfoIncluded === false,
    'Traffic ledger declares its privacy-preserving URL handling.'
  );

  return {
    chromiumOnlyCounts: countChromiumOnlyArtifacts(artifacts),
    trafficEntryCount: trafficEntries.length
  };
}

function verifyWorkflowResult(workflowResult, receivedSeed) {
  assert(Array.isArray(workflowResult?.initialModuleIds), 'Workflow returned module inventory.');
  for (const expectedModule of ['burp-bridge', 'document-acquisition', 'osint-seed', 'latent-features']) {
    assert(
      workflowResult.initialModuleIds.includes(expectedModule),
      `Workflow inventory includes ${expectedModule}.`
    );
  }
  assert(
    workflowResult.targetUrlControls?.disclosureInitiallyClosed === true &&
      workflowResult.targetUrlControls?.exactReveal === true &&
      workflowResult.targetUrlControls?.exactClipboardPayloads === true &&
      workflowResult.targetUrlControls?.exactOutputPreviews === true &&
      workflowResult.targetUrlControls?.outputSelectorOptionCount === 4 &&
      workflowResult.targetUrlControls?.progressiveHomeOrderVerified === true &&
      workflowResult.targetUrlControls?.exactNotices === true &&
      workflowResult.targetUrlControls?.actionCount === 4 &&
      workflowResult.targetUrlControls?.queryShapeVerified === true &&
      workflowResult.targetUrlControls?.focusRetained === true &&
      workflowResult.targetUrlControls?.liveStatusRegion === true,
    'Target URL disclosure and URL, parameter, GET, and POST clipboard controls pass exact browser checks.'
  );
  assert(
    workflowResult.scope?.inScopeDisposition === 'in-scope' &&
      workflowResult.scope?.inScopeMatchedRuleIds?.includes('smoke-local-origin') &&
      ['ok', 'partial'].includes(workflowResult.scope?.inScopeAutomaticStatus),
    'Executable scope allows the matched local background action.'
  );
  assert(
    workflowResult.scope?.reviewDisposition === 'review' &&
      workflowResult.scope?.reviewBasis === 'default' &&
      workflowResult.scope?.reviewTrafficEntryCount === 0 &&
      workflowResult.scope?.reviewAutomaticStatus === 'error' &&
      workflowResult.scope?.reviewAutomaticErrorCodes?.includes('TRAFFIC_SCOPE_BLOCKED'),
    'Executable scope blocks the review-default background action.'
  );
  assert(
    workflowResult.trafficView?.summaryCardCount >= 4 && workflowResult.trafficView?.rowCount > 0,
    'Traffic Ledger view renders its summary and endpoint rows for screenshot coverage.'
  );

  assert(workflowResult.search?.searchTabCount >= 3, 'Search Workbench created expected tracked search tasks.');
  assert(workflowResult.search?.builtInProfileCount === 3, 'Search Workbench exposes three built-in OSINT profiles.');
  assert(
    JSON.stringify(workflowResult.search?.freshDefaultEngineIds) === JSON.stringify(['google']),
    'A fresh Search Workbench uses Google as its sole selected default engine.'
  );
  assert(
    workflowResult.search?.operatorCatalogRowCount >= 50,
    'Search Workbench renders the complete cross-engine operator catalog.'
  );
  assert(
    workflowResult.search?.dorkSuite?.taskCount === 5 &&
      workflowResult.search?.dorkSuite?.mode === 'dork-suite' &&
      [
        ['google', 'after'],
        ['bing', 'prefer'],
        ['duckduckgo', 'ddg-semantic']
      ].every(([dialect, advancedOperatorId]) =>
        workflowResult.search?.dorkSuite?.dialects?.includes(dialect) &&
        workflowResult.search?.dorkSuite?.engineOutputs?.some(
          (output) =>
            output.dialect === dialect &&
            output.operatorIds?.includes(advancedOperatorId)
        )
      ) &&
      workflowResult.search?.dorkSuite?.previewEntries?.length === 5 &&
      workflowResult.search?.dorkSuite?.engineOutputs?.length === 5 &&
      workflowResult.search.dorkSuite.engineOutputs.every(
        (output) =>
          output.operatorIds?.includes('site') &&
          output.query?.includes('site:127.0.0.1')
      ) &&
      workflowResult.search?.dorkSuite?.catalogReviewedAt === '2026-09-09' &&
      workflowResult.search?.dorkSuite?.previewQuery?.includes('site:127.0.0.1'),
    'Dork Suite runs a bounded Google, Bing, and DuckDuckGo preview with reportable metadata.'
  );
  assert(
    workflowResult.search?.nerdSuite?.taskCount === 4 &&
      workflowResult.search?.nerdSuite?.mode === 'nerd' &&
      workflowResult.search?.nerdSuite?.surfaceMode === 'get' &&
      workflowResult.search?.nerdSuite?.surfaceMethod === 'get' &&
      workflowResult.search?.nerdSuite?.resultCount > 0 &&
      workflowResult.search?.nerdSuite?.resultUrls?.some((url) => url.includes('/docs/readme.txt')) &&
      workflowResult.search?.nerdSuite?.portablePreview?.length === 4 &&
      workflowResult.search.nerdSuite.portablePreview.every(
        (entry) => !/\bsite:/i.test(entry.query ?? '')
      ) &&
      workflowResult.search?.nerdSuite?.keywordPassCounts?.acquisitionProject === 2 &&
      workflowResult.search?.nerdSuite?.keywordPassCounts?.legacyPortal === 2 &&
      JSON.stringify(workflowResult.search?.nerdSuite?.roundRobinTerms) ===
        JSON.stringify([
          'acquisition project',
          'legacy portal',
          'acquisition project',
          'legacy portal'
        ]) &&
      workflowResult.search?.nerdSuite?.surfaceHostBound === true &&
      workflowResult.search?.nerdSuite?.queries?.some((query) =>
        query.includes('acquisition project')
      ) &&
      workflowResult.search?.nerdSuite?.queries?.some((query) => query.includes('legacy portal')) &&
      workflowResult.search?.nerdSuite?.candidateHighlightVerified === true &&
      workflowResult.search?.nerdSuite?.topFramePickerVerified === true &&
      workflowResult.search?.nerdSuite?.fingerprintRendered === true,
    'Site Search highlights and picks a top-frame GET control, iterates two keyword passes without site: syntax, records parsed results, and renders its aggregate fingerprint.'
  );
  assert(
    workflowResult.search?.nerdPostSuite?.taskCount === 1 &&
      workflowResult.search?.nerdPostSuite?.mode === 'nerd' &&
      workflowResult.search?.nerdPostSuite?.surfaceMode === 'form' &&
      workflowResult.search?.nerdPostSuite?.surfaceMethod === 'post' &&
      workflowResult.search?.nerdPostSuite?.discoveredSafeFixedParams?.corpus === 'knowledge' &&
      workflowResult.search?.nerdPostSuite?.resultCount > 0 &&
      workflowResult.search?.nerdPostSuite?.resultUrls?.some((url) => url.includes('from=nerd-post')),
    'NERD mode runs a discovered POST site search and records parsed result output.'
  );
  assert(
    workflowResult.search?.nerdDynamicSuite?.taskCount === 1 &&
      workflowResult.search?.nerdDynamicSuite?.mode === 'nerd' &&
      workflowResult.search?.nerdDynamicSuite?.surfaceMode === 'form' &&
      workflowResult.search?.nerdDynamicSuite?.surfaceMethod === 'dynamic' &&
      workflowResult.search?.nerdDynamicSuite?.resultCount > 0 &&
      workflowResult.search?.nerdDynamicSuite?.resultUrls?.some((url) =>
        url.includes('from=nerd-dynamic')
      ),
    'NERD mode runs a JavaScript-driven site widget and records parsed result output.'
  );
  assert(
    workflowResult.search?.nerdTemplateSuite?.taskCount === 1 &&
      workflowResult.search?.nerdTemplateSuite?.mode === 'nerd' &&
      workflowResult.search?.nerdTemplateSuite?.surfaceMode === 'template' &&
      workflowResult.search?.nerdTemplateSuite?.searchUrl?.includes('section=template') &&
      workflowResult.search?.nerdTemplateSuite?.resultCount > 0 &&
      workflowResult.search?.nerdTemplateSuite?.resultUrls?.some((url) => url.includes('/docs/readme.txt')),
    'NERD mode runs a reviewed URL template and records parsed result output.'
  );
  assert(workflowResult.search?.yandexOrBaiduPresent === false, 'Yandex and Baidu are absent from UI text.');

  assert(
    workflowResult.latentFeatures?.candidateCount >= 3,
    'Latent Features correlated bundle, runtime, and local candidates.'
  );
  assert(
    workflowResult.latentFeatures?.runtimeCandidatePresent === true,
    'Latent Features retained a delivered runtime candidate.'
  );
  assert(
    workflowResult.latentFeatures?.localCandidatePresent === true,
    'Latent Features retained a reversible local candidate.'
  );
  assert(
    ['ok', 'partial'].includes(workflowResult.latentFeatures?.lateDiscoveryStatus) &&
      workflowResult.latentFeatures?.newFeatureFlashVerified === true &&
      workflowResult.latentFeatures?.onOffControlsPresent === true,
    'Feature Switchboard flashes a newly discovered feature and presents explicit ON/OFF controls.'
  );
  assert(
    ['ok', 'partial'].includes(workflowResult.latentFeatures?.enableStatus) &&
      workflowResult.latentFeatures?.enabledLocalValue === true &&
      workflowResult.latentFeatures?.enabledPanelPresent === true &&
      workflowResult.latentFeatures?.enabledPanelHighlighted === true &&
      workflowResult.latentFeatures?.codeDiffVerified === true &&
      workflowResult.latentFeatures?.pageAdditionVerified === true,
    'Feature Switchboard ON applies the flag and highlights its virtual code and observed page addition.'
  );
  assert(
    ['ok', 'partial'].includes(workflowResult.latentFeatures?.disableStatus) &&
      workflowResult.latentFeatures?.disabledLocalValue === false &&
      workflowResult.latentFeatures?.disabledPanelPresent === false &&
      workflowResult.latentFeatures?.disabledPanelRemovalHighlighted === true &&
      workflowResult.latentFeatures?.pageRemovalVerified === true,
    'Feature Switchboard OFF applies the flag and highlights its observed page removal.'
  );
  assert(
    ['ok', 'partial'].includes(workflowResult.latentFeatures?.secondEnableStatus) &&
      workflowResult.latentFeatures?.activeChangeCountBeforeRestore === 2 &&
      ['ok', 'partial'].includes(workflowResult.latentFeatures?.restoreStatus) &&
      workflowResult.latentFeatures?.exactContainerRestore === true,
    'Feature Switchboard retains multiple changes and Restore All exactly restores the shared storage container.'
  );
  const javascriptAnalysis = workflowResult.latentFeatures?.javascriptAnalysis;
  assert(
    javascriptAnalysis?.rawDocumentAssessmentPresent === true &&
      javascriptAnalysis.queuedPassiveStartupSerialized === true &&
      javascriptAnalysis.multiCandidateRecoveryRetained === true &&
      javascriptAnalysis.passiveAssessmentCount > 0 &&
      javascriptAnalysis.passiveAppAssessmentPresent === true &&
      javascriptAnalysis.passiveReloadCountDelta === 0,
    'Static JavaScript analysis retains /app.js without reloading and multi-candidate recovery remains coherent.'
  );
  assert(
    ['ok', 'partial'].includes(javascriptAnalysis?.startupActionStatus) &&
      javascriptAnalysis.startupReloadCountDelta === 1 &&
      javascriptAnalysis.startupScopeDisposition === 'in-scope' &&
      javascriptAnalysis.startupInstrumentationAvailable === true &&
      javascriptAnalysis.startupInstrumentationIntegrity === 'page-world-unverified' &&
      javascriptAnalysis.sourceBindingMatches === true,
    'The bounded startup observation is explicitly in scope, instrumented, and limited to one reload.'
  );
  assert(
    javascriptAnalysis?.runtimeStats?.networkRequestCount > 0 &&
      javascriptAnalysis.runtimeStats.storageWriteCount > 0 &&
      javascriptAnalysis.runtimeStats.workerCount > 0 &&
      javascriptAnalysis.runtimeStats.eventCount > 0 &&
      javascriptAnalysis.evidenceRecordCount > 0 &&
      javascriptAnalysis.allCellEvidenceRefsResolve === true,
    'The bounded startup observation serializes network, storage, worker, and runtime evidence.'
  );
  assert(
    [
      'traffic-window',
      'behavior-network'
    ].every((testId) => javascriptAnalysis?.observedCellIds?.includes(testId)),
    'The workflow result preserves extension-verified observed-cell references.'
  );
  assert(
    [
      'behavior-dom-ui',
      'behavior-client-storage',
      'behavior-persistence-background-realtime'
    ].every((testId) => javascriptAnalysis?.unverifiedObservedCellIds?.includes(testId)),
    'The workflow result keeps page-world observations explicitly unverified.'
  );
  assert(
    javascriptAnalysis?.reportScriptAssessmentCount > 0 &&
      javascriptAnalysis.reportJavascriptTestRunId === javascriptAnalysis.startupTestRunId &&
      javascriptAnalysis.reportHasJavascriptContext === true,
    'The serialized report summary retains its JavaScript assessment and startup-observation context.'
  );

  const passiveWarnings = workflowResult.bridgePassive?.warnings ?? [];
  assert(
    passiveWarnings.some((warning) => warning.code === 'PASSIVE_MODE_PROVENANCE_LIMIT'),
    'Passive collection returned provenance warning.'
  );

  const sourceCapture = workflowResult.bridgePassive?.export;
  const reportResult = workflowResult.report;
  const report = reportResult?.payload;
  const embeddedSourceCapture = report?.sourceCapture;
  assert(report?.kind === 'blanche.tear-sheet', 'Report workflow returned a BLANCHE tear sheet.');
  assert(report?.schemaVersion === '1.0.0', 'Report workflow returned the supported schema version.');
  assert(
    embeddedSourceCapture?.exportMetadata?.exportId === sourceCapture?.exportMetadata?.exportId &&
      report?.metadata?.sourceExportId === embeddedSourceCapture?.exportMetadata?.exportId,
    'Report source capture and metadata export IDs match the passive capture.'
  );
  assert(
    embeddedSourceCapture?.summary?.artifactCount === sourceCapture?.summary?.artifactCount &&
      report?.evidenceSummary?.artifactCount === embeddedSourceCapture?.summary?.artifactCount,
    'Report source capture and evidence artifact counts match the passive capture.'
  );
  assert(report?.target?.hostname === '127.0.0.1', 'Report target hostname matches the smoke target.');
  assert(
    Array.isArray(report?.limitations) && report.limitations.length > 0,
    'Report workflow returned capture limitations.'
  );
  const reportProvenance = report?.evidenceSummary?.provenance;
  assert(
    reportProvenance &&
      reportProvenance.observed + reportProvenance.inferred + reportProvenance.unavailable ===
        report.evidenceSummary.artifactCount,
    'Report workflow returned complete provenance totals.'
  );
  assert(
    reportResult?.controls &&
      Object.keys(reportResult.controls).length === 7 &&
      Object.values(reportResult.controls).every(Boolean),
    'Report workflow exposed stakeholder/JSON modes, downloads, copy, and full JSON controls.'
  );

  assert(
    workflowResult.documents?.documentCount >= 3,
    'Document Acquisition recorded document inventory.'
  );
  assert(
    workflowResult.documents?.acquiredDocumentCount >= 2,
    'Document Acquisition acquired documents.'
  );
  assert(
    ['acquired', 'reviewed'].includes(workflowResult.documents?.autoCapturedDocumentStatus) &&
      workflowResult.documents?.autoCapturedDocumentKeywordCount > 0,
    'Document Acquisition auto-acquired and analyzed the scoped CSV before manual scanning.'
  );
  assert(
    workflowResult.documents?.interestingDocumentCount >= 1,
    'Document Acquisition found interesting document indicators.'
  );
  assert(
    workflowResult.documents?.indexedSearchCount === 7,
    'Document Acquisition launched indexed document searches.'
  );
  assert(
    workflowResult.documents?.clearStatus === 'ok',
    'Document Acquisition clear inventory action completed.'
  );

  assert(workflowResult.disabledOsintSeed?.status === 'error', 'Disabled OSINT Seed module rejected action.');
  assert(workflowResult.osintSeed?.data?.delivered === true, 'OSINT Seed reported successful delivery.');
  assert(
    workflowResult.osintSeed?.data?.relatedHostCount >= 3,
    'OSINT Seed found related hosts from page context.'
  );
  if (receivedSeed) {
    assert(receivedSeed.kind === 'blanche.osint-seed', 'Loopback received a BLANCHE OSINT seed payload.');
    assert(
      (receivedSeed.browserContext?.relatedHosts?.length ?? 0) >= 3,
      'Loopback OSINT seed contains related hosts.'
    );
  }

  assert(workflowResult.interest?.bookmarkCount >= 4, 'Interest Model learned from bookmark samples.');
  assert(workflowResult.interest?.topSignalCount > 0, 'Interest Model produced top signals.');

  return {
    passiveWarningCount: passiveWarnings.length,
    reportArtifactCount: report.evidenceSummary.artifactCount,
    reportLimitationCount: report.limitations.length,
    acquiredDocumentCount: workflowResult.documents.acquiredDocumentCount,
    relatedHostCount: workflowResult.osintSeed.data.relatedHostCount,
    latentFeatureCount: workflowResult.latentFeatures.candidateCount,
    interestBookmarkCount: workflowResult.interest.bookmarkCount,
    searchTabCount: workflowResult.search.searchTabCount,
    operatorCatalogRowCount: workflowResult.search.operatorCatalogRowCount,
    dorkTaskCount: workflowResult.search.dorkSuite.taskCount,
    nerdResultCount: workflowResult.search.nerdSuite.resultCount
  };
}

function verifyTargetUrlControlsResult(workflowResult) {
  assert(workflowResult?.mode === 'target-url-controls-only', 'Target URL controls smoke returned its focused mode.');
  assert(
    workflowResult.targetUrlControls?.disclosureInitiallyClosed === true &&
      workflowResult.targetUrlControls?.exactReveal === true &&
      workflowResult.targetUrlControls?.exactClipboardPayloads === true &&
      workflowResult.targetUrlControls?.exactOutputPreviews === true &&
      workflowResult.targetUrlControls?.outputSelectorOptionCount === 4 &&
      workflowResult.targetUrlControls?.progressiveHomeOrderVerified === true &&
      workflowResult.targetUrlControls?.exactNotices === true &&
      workflowResult.targetUrlControls?.actionCount === 4 &&
      workflowResult.targetUrlControls?.queryShapeVerified === true &&
      workflowResult.targetUrlControls?.focusRetained === true &&
      workflowResult.targetUrlControls?.liveStatusRegion === true &&
      workflowResult.targetUrlControls?.pollPersistenceVerified === true &&
      workflowResult.targetUrlControls?.refreshPersistenceVerified === true &&
      workflowResult.targetUrlControls?.closePersistenceVerified === true &&
      ['target-url', 'search-throttles', 'nerd-template-composer', 'operator-catalog', 'module-settings'].every(
        (family) => workflowResult.targetUrlControls?.disclosureFamiliesVerified?.includes(family)
      ),
    'Target URL controls and representative console disclosures preserve open and closed state across live rerenders.'
  );
}

function countChromiumOnlyArtifacts(artifacts) {
  const chromiumOnlyCategories = new Set([
    'blob',
    'data-url',
    'storage-key',
    'indexeddb-database',
    'cache',
    'service-worker',
    'runtime-indicator'
  ]);
  const counts = {};
  for (const artifact of artifacts) {
    const category = artifact.category ?? 'unknown';
    const chromiumOnly =
      chromiumOnlyCategories.has(category) ||
      artifact.kind?.startsWith('instrumented-') ||
      artifact.discoveredBy?.includes('instrumentation') ||
      String(artifact.url ?? '').startsWith('blob:') ||
      String(artifact.url ?? '').startsWith('data:');

    if (chromiumOnly) {
      counts[category] = (counts[category] ?? 0) + 1;
    }
  }
  return counts;
}

function formatCounts(counts) {
  return Object.entries(counts)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([category, count]) => `${category}=${count}`)
    .join(', ');
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Smoke verification failed: ${message}`);
  }
}

async function waitFor(callback, timeoutMs, intervalMs, label) {
  const startedAt = Date.now();
  let lastError;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const value = await callback();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  throw new Error(
    `Timed out waiting for ${label}${lastError ? `: ${lastError.message ?? String(lastError)}` : ''}`
  );
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`GET ${url} failed with ${response.status}`);
  }
  return await response.json();
}

class CdpClient {
  static async connect(webSocketUrl) {
    const socket = new WebSocket(webSocketUrl);
    const client = new CdpClient(socket);
    await client.opened;
    return client;
  }

  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.opened = new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true });
      socket.addEventListener('error', reject, { once: true });
    });
    socket.addEventListener('message', (event) => this.handleMessage(event.data));
    socket.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        pending.reject(new Error('CDP socket closed.'));
      }
      this.pending.clear();
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    const message = {
      id,
      method,
      params
    };
    const pending = new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
    this.socket.send(JSON.stringify(message));
    return pending;
  }

  handleMessage(rawMessage) {
    const message = JSON.parse(rawMessage);
    if (!message.id) {
      return;
    }

    const pending = this.pending.get(message.id);
    if (!pending) {
      return;
    }

    this.pending.delete(message.id);
    if (message.error) {
      pending.reject(new Error(message.error.message ?? JSON.stringify(message.error)));
      return;
    }

    pending.resolve(message.result ?? {});
  }

  close() {
    this.socket.close();
  }
}

function parseSmokeOptions(args) {
  const supported = new Set([
    '--tear-sheet-only',
    '--target-url-controls-only',
    '--site-search-only'
  ]);
  const unsupported = args.filter((argument) => !supported.has(argument));
  if (unsupported.length > 0) {
    throw new Error(`Unknown smoke option${unsupported.length === 1 ? '' : 's'}: ${unsupported.join(', ')}`);
  }
  const selectedModes = [
    '--tear-sheet-only',
    '--target-url-controls-only',
    '--site-search-only'
  ].filter((option) => args.includes(option));
  if (selectedModes.length > 1) {
    throw new Error('Choose only one focused smoke mode.');
  }
  return {
    tearSheetOnly: args.includes('--tear-sheet-only'),
    targetUrlControlsOnly: args.includes('--target-url-controls-only'),
    siteSearchOnly: args.includes('--site-search-only')
  };
}

await main(parseSmokeOptions(process.argv.slice(2)));
