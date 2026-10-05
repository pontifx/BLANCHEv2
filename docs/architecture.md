# Architecture

## Chromium side

Core pieces:
- `background/host.ts`
  - module registry
  - runtime message routing
  - persisted module state
  - session tracking
  - export persistence
- `background/searchCoordinator.ts`
  - persisted search sessions and per-task lifecycle
  - global low-concurrency scheduling with same-engine and same-query throttles
  - background search tabs, rendered-result extraction, canonicalization, and deduplication
  - explicit `manual-required` state for anti-automation pages
- `background/findingsManager.ts`
  - scored, deduplicated tester findings
  - artifact-derived question cards and extension badge count
- `background/trafficLedgerManager.ts`
  - synchronous MV3 `webRequest` listener registration and lifecycle correlation
  - privacy-preserving endpoint aggregation in a separate bounded storage record
  - active-policy re-scoping, filtered queries, and portable ledger export
- `shared/scopePolicy.ts` and `shared/trafficLedger.ts`
  - executable scope parsing/evaluation, endpoint canonicalization, taxonomy inference, scoring,
    aggregation, and summaries
- `background/dependencyIntelligence.ts`
  - known-library version detection in scripts already loaded by the page
  - cached npm latest-release metadata and public OSV advisory lookup
- `shared/contracts.ts`
  - explicit module contract
  - session/log/runtime message shapes
- `shared/runtimeBus.ts`
  - typed request/response wrapper between UI surfaces and the background host
- `shared/operatorConsole.ts`
  - shared Home/Search/Findings/Traffic/Documents/Report/Labs shell used by the side panel and
    DevTools panel
  - progressive target/output, action, live-status, result, workbench, configuration, and raw-evidence
    hierarchy with explicit retained-versus-displayed counts for bounded lists
- `modules/burpBridge`
  - descriptor-driven module metadata
  - background orchestration
  - page snapshot collector
  - artifact assembly logic
- `modules/osintSeed`
  - Chromium-side OSINT seed derivation from the active tab
  - related-host extraction from browser-visible references
  - Burp handoff for OSINT seeding
- `modules/latentFeatures`
  - throttled, cache-preferred reads of script resources already loaded by the page
  - direct capture of bounded source text when the current tab displays a raw JavaScript document
  - versioned transform, likely-purpose, behavior-maturity, review-priority, and coverage analysis
  - one-reload startup observation that correlates static claims with bounded document-start runtime events
  - compact-source, storage, bootstrap-global, DOM, and delivered-response candidate correlation
  - exact-origin, one-at-a-time browser-storage probing with persisted rollback
- `shared/latentFeatureWorkbench.ts`
  - persisted script assessments, startup-observation matrix, candidate evidence, scan statistics, and
    active-probe state rendered by both operator surfaces

## OSINT layer

`osint-orchestrator`
- local Node-based passive OSINT CLI
- built-in collectors for DNS, HTTP, and TLS metadata
- optional wrappers for passive external tools already on PATH
- normalized report output plus markdown summary

`shared-schema/src/osint.ts`
- OSINT seed envelope
- OSINT report envelope
- shared guardrail and narrative fields

`burp-extension`
- accepts browser exports, OSINT seeds, and OSINT reports
- stores the latest OSINT seed/report in the same suite tab
- can run the local CLI automatically when a seed arrives

## Module contract

Modules declare:
- id
- name
- version
- description
- required permissions
- required host permissions
- execution surfaces
- commands
- settings schema
- collectors
- exporters
- UI contributions
- manifest contributions

The build script reads module descriptors and merges permissions/content-script contributions into the final extension manifest.

## Burp Bridge flow

Current collection flow:
1. A collection is triggered one of two ways:
   - the operator runs a Burp Bridge command from the side panel or DevTools panel (reload +
     instrumented or explicit passive), or
   - the background host auto-triggers a passive (non-reloading) collection whenever
     `chrome.webNavigation.onCompleted` fires for a tab's top-level frame on an `http(s)` page,
     as long as the Burp Bridge module is enabled and its `autoCaptureOnNavigation` setting
     (default on) hasn't been turned off. This is what lets ordinary browsing — not just
     explicit operator action — populate the Burp-side host/endpoint pairing.
2. Background host creates a per-session record.
3. If configured, the target tab reloads and the host waits for top-level completion.
4. Chromium frame metadata is collected via `chrome.webNavigation.getAllFrames`.
5. Frame-local page snapshots are collected via `chrome.scripting.executeScript(..., world: "MAIN")`.
6. In instrumented mode, the content bridge requests the page-instrumentor event buffer collected from `document_start`.
7. The module assembles artifacts, warnings, errors, and visibility gaps, then asks the central
   traffic manager for the tab-scoped ledger.
8. The export builder produces a versioned `BLANCHE` JSON document with the embedded ledger.
9. The latest export is persisted and rendered back in the operator UI.

Burp export and OSINT-seed handoffs serialize JSON into a CORS-simple `text/plain` POST with
credentials omitted. The proxy and loopback bridges parse the body as JSON regardless of the
transport content type. This avoids browser preflight failures against an older or intercepted
bridge response; opaque responses count as dispatched, while connection and timeout failures still
trigger the configured fallback.

## Traffic ledger flow

1. The manager registers non-blocking request listeners synchronously when the service worker is
   constructed, then restores its separate bounded store.
2. Request lifecycle events are correlated by request ID and redirect hop. URL values are removed
   before persistence; request/response header names and parsed request-body field names are kept,
   but their values are not.
3. Canonical identity includes method, scheme, host, effective port, templated path, and sorted
   query names. Repeated observations merge without collapsing different HTTP methods.
4. The active engagement policy assigns scope with matched rule IDs, confidence, and reason codes.
   Existing records are re-evaluated when read, so activating a policy updates the current view
   without destroying the original endpoint evidence.
5. Boundary, ownership, environment, role, access, operation, and data-class dimensions are scored
   by `blanche.traffic-priority.v1`. Applied factors remain attached to the entry. Scope never
   modifies priority.
6. Capture begins with an explicitly in-scope request or an in-scope top-level target. Related
   requests in that target tab remain observable and receive their own disposition. Automatic
   Burp snapshots, OSINT analysis, library reads, and document retrieval require an in-scope
   decision.
7. The Traffic view queries the current tab and exports canonical JSON or JSONL. Burp renders the
   same embedded contract and tolerates older exports that do not contain it.

## Site tear sheet flow

1. The Report surface resolves the active site from the current tab and can invoke a forced full
   instrumented capture (with reload) or a passive snapshot for that page.
2. Report assembly retains the complete source capture and correlates persisted host state by exact
   normalized hostname. Correlated state includes findings, search sessions/tasks/results,
   acquired-document records, Delivered JavaScript assessments and startup-observation coverage,
   latent-feature scan evidence, and activity entries; their timestamps
   remain visible because host correlation does not prove they belong to the same capture session.
3. The resulting report model keeps source identifiers, timestamps, collector status, artifact
   provenance, warnings, errors, and visibility gaps so the presentation remains traceable to the
   underlying observations.
4. Stakeholder mode projects that model into an explanatory tear sheet. Raw captured values are
   masked in the rendered report, while counts, categories, evidence descriptions, provenance, and
   collection limitations remain visible.
5. JSON Evidence mode serializes the full report model, including its source browser capture and
   site-correlated records. Operators can download the JSON or copy it to the clipboard. Because
   browser captures can retain storage values, this mode is sensitive evidence rather than a
   redacted stakeholder artifact.
6. `Download HTML` exports the current Stakeholder view; `Download JSON` and `Copy JSON` export the
   JSON Evidence view.

The report is broader than a traditional HAR in the browser-only state it can describe, including
storage, IndexedDB catalogs, Cache Storage, workers, service workers, blobs, data URLs, DOM
resources, and document-start instrumentation. It is not a full HAR implementation: BLANCHE does
not retain complete raw HTTP requests and responses, header/body values, cookies, or transaction
waterfalls. Network-level claims must therefore remain tied to Burp or another HTTP capture source.

## Provenance model

Artifact provenance uses:
- `observed`
- `inferred`
- `unavailable`

Examples:
- A dynamically created blob captured through patched `URL.createObjectURL` is `observed`.
- A blob URL only seen in the current DOM or performance entries is not treated as fully knowable; provenance is `unavailable` or `inferred`.
- Browser-reported resources and DOM nodes are generally `observed` as present, but that does not imply full creation lineage.

The site tear sheet preserves these dispositions instead of flattening all entries into confirmed
facts. It also renders collector warnings, errors, and visibility gaps alongside the affected
sections so stakeholders can distinguish observed coverage from collection limits.

## Delivered JavaScript and latent feature flow

1. The page collector reads storage, bounded bootstrap globals, feature-related DOM attributes,
   inline scripts, and URLs of scripts the page already loaded. When the current HTTP(S) tab
   directly displays a JavaScript MIME response or a `.js`/`.mjs` resource, it also captures the
   browser-rendered source text within the direct-document cap without executing it.
2. The optional loaded-library reader applies a global inter-read delay, worker cap, resource cap,
   per-resource byte cap, total-byte cap, cache preference, anonymous credentials mode, redirect
   scope checks, and no retries. Each new read requires an `in-scope` Traffic decision.
3. The versioned Delivered JavaScript rubric hashes each retained source and reports representation
   transforms, likely purposes, behavior maturity, sanitized indicators, evidence, confidence,
   review priority, and coverage gaps. Transform describes representation; review priority orders
   analyst follow-up; finding severity and validated vulnerability impact are separate concerns.
4. `Observe Startup (reloads)` requires the starting page to be explicitly `in-scope`, refuses to run
   over an active local-feature probe, starts an instrumented session, and reloads the tab exactly
   once. The final page must remain on the starting origin and explicitly in scope.
5. Document-start instrumentation retains bounded events for network requests and beacons, DOM
   mutations, storage writes, route changes, dynamic scripts and workers, WebSockets and event
   streams, feature candidates, runtime errors, and unhandled rejections. Its page-world transport
   is marked `page-world-unverified` because inspected page code can fabricate or suppress those
   messages. The startup observation correlates these leads and independently extension-recorded,
   sanitized Traffic ledger shapes with the static behavior axes in a persisted matrix. Unverified
   events do not create runtime feature candidates or per-script maturity level `3` claims.
6. The startup observation does not click, type, submit forms, replay transactions, guess inputs, or execute
   acquired code inside the extension. Its coverage is the eligible static and startup stages from
   one reload; blocked, manual, and not-observed cells preserve non-exhaustive coverage rather than
   asserting absence.
7. Candidate analysis separately correlates feature callsites and values across evidence sources.
   Hash pairs remain opaque. Unambiguous boolean-like browser-storage candidates expose ON/OFF
   values. Execution revalidates explicit scope, tab, origin, and the live value; persists one
   complete baseline per storage container; and permits several reversible changes before
   `Restore All`. A bounded top-frame structure diff records and temporarily highlights changes
   observed after the toggle without claiming causality or patching delivered bundle bytes. Stable
   candidate IDs also drive one-time new-feature flashes after a same-tab, same-origin rescan.
8. Recognized dependency versions are checked against cached npm metadata and OSV using the same
   conservative worker count and global delay. Outdated or vulnerable shipped versions become
   tester findings; this check can be disabled.

See [`javascript-analysis.md`](./javascript-analysis.md) for rubric reason codes, test stages,
limits, scope semantics, and coverage constraints.

## Search execution flow

1. `Run Search` resolves the active tab hostname when the draft has no target.
2. The default recipe creates bounded tasks for public footprint, indexed files, archives,
   JavaScript/source maps, known libraries, URL/endpoint terms, infrastructure/certificates, and
   shipped client-feature terms.
3. The scheduler defaults to one task at a time. Same-engine starts and repeated identical queries
   both default to 300 ms spacing/cooldown.
4. Each search opens in a background tab. BLANCHE waits for the rendered document, detects common
   human-verification pages, and extracts/deduplicates result links.
5. A parsed page with results or with zero results is complete. Anti-automation is never complete:
   the task remains `manual-required`, its tab remains available, and the UI exposes Copy/Open.
6. Completed result tabs close by default; all task state and evidence persist.

## Document queue flow

1. Ordinary document responses and explicit link scans enter a per-session queue.
2. Public bodies are fetched without credentials into bounded memory, hashed, deduplicated, and analyzed for
   containers/compression, URLs, and configured interesting terms.
3. Filesystem download is off by default. A reviewed item exposes an individual approval button.
4. An optional score-and-keyword rule promotes matching documents into the review queue. It does
   not start a browser download because the download API cannot expose redirect destinations for
   preflight scope checks. Every filesystem download therefore requires tester approval.

## Shared schema

`shared-schema` contains:
- TypeScript export types
- schema version constants
- JSON Schema for the export envelope

The schema currently covers:
- export metadata
- page and tab metadata
- collection metadata
- permissions state
- collector outputs
- artifact taxonomy
- executable scope policy, traffic taxonomy, priority factors, and sanitized observations
- provenance
- warnings/errors/visibility gaps
- export summary
- OSINT seed metadata
- OSINT report metadata
- tool execution summaries
- normalized OSINT findings
- report-ready narrative fields

## Burp side

The Burp project is intentionally scaffolded rather than fully integrated.

Implemented:
- Gradle/Kotlin DSL project structure
- Montoya extension entrypoint
- Suite tab registration
- Local JSON file loading
- Browser export ingest views
- OSINT seed/report ingest views
- Burp-side OSINT orchestration hook to the local CLI
- Host/endpoint pairing of Chromium-only data (see below)

Planned next steps:
- richer Swing tables and filters
- correlation between browser-only artifacts and Burp issues (not just site map/Organizer)
- stronger blob provenance visualization
- session/history management inside Burp
- configurable Burp-side OSINT settings instead of current code-level defaults

### Host/endpoint pairing

`BlancheArtifactPairing` decides, for every artifact in an ingested export, whether it is
Chromium-only (never observable as HTTP traffic: blobs, `data:` URLs, storage keys, IndexedDB,
Cache Storage, service workers, runtime indicators, and anything discovered only through page
instrumentation) and computes a single grouping key for it:
- artifacts that carry a real `http(s)` URL pair to that exact URL/host (e.g. an
  instrumented fetch to a cross-origin API endpoint that never went through the proxy);
- everything else (storage keys, IndexedDB, cache entries, blobs without a resolvable embedded
  host, etc.) is bucketed per category under the origin that produced it.

Both consumers of this key stay in sync by construction:
- `BlancheSiteMapIntegrator` creates or annotates one Burp site map entry per pairing key (in
  addition to the existing page-level summary entry), so expanding a host in Burp's site tree
  shows the Chromium-only data captured for it, highlighted cyan.
- `BlancheHostRegistry` aggregates every ingested export and OSINT payload by hostname in memory,
  keeping pages, Chromium-only endpoint/bucket groups, and OSINT seed/report data per host.
  `BlancheSuiteTab` renders this as a host/endpoint tree (instead of a single flat set of tabs
  that gets overwritten by whatever was ingested most recently); selecting a host, page, endpoint,
  or OSINT node shows only the data paired with that selection.
