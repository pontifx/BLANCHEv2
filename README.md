# BLANCHE

BLANCHE is a modular Chromium extension platform paired with a Burp Suite extension and a local passive-OSINT orchestration CLI.

Phase 1 status:
- Chromium extension core is implemented with a background service worker, side panel UI, DevTools panel, module registry, typed runtime bus, persisted module settings, recent log buffer, session tracking, and a versioned JSON export path.
- Module `burp-bridge` is implemented as module `001`.
- Module `osint-seed` is implemented for public-OSINT target seeding from the current tab.
- Module `document-acquisition` is implemented for indexed document discovery, in-memory review, a scored queue, explicit downloads, and opt-in score-plus-keyword download rules.
- Module `latent-features` is implemented for an evidence-backed Delivered JavaScript purpose
  rubric, a bounded one-reload startup observation, four-stage test plans, throttled discovery of
  shipped client feature controls, runtime flag/config correlation, and one-at-a-time reversible
  browser-storage probing.
- Search Workbench includes a sourced cross-engine operator catalog that classifies Google, Bing,
  and DuckDuckGo syntax as documented, observed, fragile, deprecated, or unsupported.
- Google is the default search destination. Bing, DuckDuckGo, Yahoo, Shodan, and crt.sh remain
  explicit options, and saved profiles retain their reviewed engine selections.
- The engine-aware Dork Suite builds bounded, target-scoped query sets in each selected core
  engine's own dialect. Site Search can instead route a reviewed portable suite through an
  explicitly selected HTTP(S) search control or GET URL template.
- Tracked advanced search sessions read rendered result pages, deduplicate links, distinguish zero results from anti-automation, and retain exact copyable queries for manual completion.
- A score-aware traffic ledger passively correlates Chromium requests into method-aware endpoint shapes, applies versioned engagement scope, records a transparent triage score, and exports sanitized JSON/JSONL for downstream tooling.
- The tester UI follows a progressive operator hierarchy: Home, Search, Findings, Traffic, Documents,
  Report, and Labs. The earth-tone terminal interface puts the active target/output transformer first,
  the bounded search action second, current status/results next, and configuration or raw evidence
  progressively deeper. Traffic owns scope policies and the endpoint ledger; Report turns the current
  site's browser capture and related tester activity into stakeholder HTML or full JSON evidence.
- Shared export and OSINT schemas live in [`shared-schema`](./shared-schema).
- Burp Suite has a Java extension scaffold with a custom suite tab, proxy-native automatic ingestion, site map annotation/highlighting for Chromium-only visibility, and a Burp-side OSINT coordinator that can invoke the local CLI.
- A local passive-OSINT orchestrator lives under [`osint-orchestrator`](./osint-orchestrator).

## Repository layout

```text
/chromium-extension
/burp-extension
/osint-orchestrator
/shared-schema
/docs
/scripts
```

## Chromium extension

1. Install dependencies:

   ```powershell
   npm install
   ```

2. Build the extension:

   ```powershell
   npm run build
   ```

3. Load the unpacked extension from:

   ```text
   chromium-extension
   ```

   The build writes compiled assets into `chromium-extension/dist` and a loadable `chromium-extension/manifest.json` that points at those built files.

4. Open the extension side panel or the DevTools panel named `BLANCHE`.

   The `[01 Target / Output]` console exposes a multi-tool selector for the exact URL, raw query
   parameters, a minimal HTTP/1.1 GET request, or a constructed form POST template. The selected
   output is visible for review before copying; dedicated copy actions remain available for every
   representation. The POST template moves the current URL query into the request body and represents
   an operator-created starting point rather than an observed request. The full URL disclosure and
   other disclosure state are retained across background polling, manual refreshes, and navigation.

5. From Home, choose:
   - `Run Search` to start the default target-aware recipe, or
   - `View Documents` to review the in-memory acquisition queue.

6. Use `Search` to:
   - run an ad hoc query from `Run`,
   - generate per-engine target queries from `Dork Suite`,
   - pick, scan, or supply a reviewed search endpoint and submit a portable suite from `Site Search`, or
   - inspect source, compatibility, replacement, and generation-safety details under `Operators`.

7. Use `Traffic` to:
   - create an engagement profile with structured include/exclude rules,
   - activate its scope policy and bundled module settings,
   - filter method-aware endpoints by scope and minimum priority, and
   - download the sanitized ledger as JSON or JSONL.

8. Use `Report` to:
   - choose `Capture Full Site (reloads)` or `Passive Snapshot` to refresh the active tab's evidence,
   - review a stakeholder-oriented tear sheet with raw values masked,
   - inspect the complete JSON Evidence view, and
   - use `Download HTML`, `Download JSON`, or `Copy JSON` for the intended audience.

9. Use `Burp Bridge` under Labs to:
   - run a reload-backed collection, or
   - run a passive snapshot

10. Use `OSINT Seed` under Labs to:
   - derive a public-OSINT seed from the current tab, and
   - hand that seed to Burp for orchestration

11. Use `Documents` to:
   - inspect discovered bodies in memory without writing files by default,
   - auto-capture documents encountered while browsing,
   - approve individual downloads or configure a keyword-and-score rule, and
   - review compression/container signals, extracted URLs, and interesting keyword hits.

12. Use `JavaScript & Latent Features` under Labs to:
   - select `Analyze Current Tab` to classify delivered source as readable, minified, bundled,
     packed, or obfuscated and score its likely purpose, behavior maturity, coverage, and review
     priority,
   - analyze bounded inline code, already-loaded script resources, and the displayed text when the
     current tab is a raw `.js` or `.mjs` document,
   - select `Observe Startup (reloads)` on a tab explicitly marked `in-scope` to reload once and
     correlate the static rubric with bounded startup runtime events,
   - correlate flag-shaped storage, bootstrap globals, delivered configuration, inline code, and
     already-loaded script resources,
   - keep loaded-library reads at one worker with global spacing by default, and
   - use the Feature Switchboard to turn eligible local flags ON or OFF, see highlighted virtual
     configuration and observed page-structure diffs, and restore every exact original storage
     container.

Transform labels describe how source is represented. Review priority orders analyst follow-up;
finding severity and validated vulnerability impact remain separate. The startup observation records
network, DOM, storage, routing, worker, realtime, and runtime-error events where visible. It does
not interact with controls or claim exhaustive code-path coverage. Same-window page instrumentation
is labeled `page-world-unverified`; extension-recorded Traffic ledger evidence is shown separately,
and unverified events do not raise an individual script to runtime maturity.

See [`docs/javascript-analysis.md`](./docs/javascript-analysis.md) for the rubric, staged test plan,
startup scope gate, collection caps, runtime evidence, scoring, and coverage limitations.
See [`docs/latent-feature-discovery.md`](./docs/latent-feature-discovery.md) for evidence sources,
hard throttling behavior, and probe/rollback semantics.
See [`docs/feature-switchboard.md`](./docs/feature-switchboard.md) for reversible ON/OFF controls,
new-feature flashes, highlighted code/page diffs, and recovery invariants.
See [`docs/tester-workflow.md`](./docs/tester-workflow.md) for search completion states, findings,
question cards, throttles, and document queue behavior.
See [`docs/site-tear-sheet.md`](./docs/site-tear-sheet.md) for report contents, export modes,
provenance, sensitive-data handling, and capture limitations.
See [`docs/traffic-ledger.md`](./docs/traffic-ledger.md) for scope syntax, taxonomy, scoring,
redaction, and downstream handoff guidance.
See the [`cross-engine search operator matrix`](./docs/search-operator-matrix.md) for the catalog's
sources, status meanings, engine-wide caveats, and supported replacements.

## Search Workbench

Search Workbench separates the existing ad hoc query builder from two generated workflows. Before
launching either workflow, enter only domains, subdomains, or URLs that are inside the authorized
engagement scope. A target is required; an unconfigured Traffic scope policy or a generated query
does not grant authorization.

### Cross-engine operator catalog

Open `Search`, then `Operators`, to inspect the normalized Google, Bing, and DuckDuckGo matrix.
Each engine cell exposes its syntax, semantics, compatibility status, caveats, replacement where
one exists, generation-safety decision, applicable search surface, and supporting source links.
Deprecated and unsupported entries are retained as negative knowledge so stale operator lists do
not silently become generated queries. Observed and fragile entries remain visibly qualified.

The catalog snapshot is also available in the
[`search operator compatibility matrix`](./docs/search-operator-matrix.md). Search indexes and
ranking systems remain incomplete and change over time; a zero-result query is not proof that the
targeted material does not exist.

### Engine-aware Dork Suite

1. Open `Search`. Google is selected for a fresh or reset draft. Use `Configure` to add or replace
   it with Bing or DuckDuckGo for the generated suite.
   Yahoo, Shodan, and crt.sh remain available to the ad hoc builder but are not Dork Suite dialects.
2. Open `Dork Suite` and enter one or more authorized target sites. Choose the desired categories:
   authentication surfaces, indexed documents, API surface, client artifacts, directory listings,
   and recent changes.
3. Optionally add focus terms separated by newlines, commas, or semicolons and set `Maximum
   submissions` from 1 through 60. BLANCHE repeats the selected templates for every normalized,
   deduplicated term, then applies the cap before launch to prevent a tab storm.
4. Review the exact query preview, destination dialect, operator IDs, and engine-specific warnings.
5. Select the `Run … Dork(s)` control. BLANCHE commits a tracked task for every previewed submission before it
   begins processing the suite with the configured search throttles.

Recipes use engine-specific forms instead of blindly copying Google syntax. For example, current
Google date syntax is not sent to Bing or DuckDuckGo, Bing's one-term field operators are composed
accordingly, and DuckDuckGo's relaxed or experimental behavior is called out in the preview.
Only catalog entries approved for generation are used; deprecated and unsupported entries are
excluded.

### Site Search

Site Search is the visible workflow for the internal NERD execution mode. It is intended for an
HTTP(S) site-search function that the user is authorized to exercise.

1. Navigate the active tab to the authorized site and open `Search` > `Site Search`.
2. Use `Pick Search on Page` and click a search field in the page's top frame. You can also use
   `Scan Page`, review each captured destination, method, selector, and source hint, then use
   `Highlight` to locate the field before selecting it. As an alternative, add a reviewed HTTP(S)
   GET URL containing exactly one `{query}` placeholder.
3. Select the saved surface, enter authorized target sites, choose categories, add optional focus
   terms separated by newlines, commas, or semicolons, and set the 1-through-60 submission cap.
4. Review every exact probe and select `Run … Site Search Probe(s)`.

For a GET surface or reviewed URL template, BLANCHE builds the destination URL with the generated
query. For POST or JavaScript-driven form surfaces, it returns to the captured page, fills the
saved search input, and submits through the captured control. The portable dork syntax is sent
unchanged, so the destination site decides how each token is interpreted. Captured page selectors
and routes can become stale, and authentication, anti-automation, or site-side validation can
require manual completion. Picking, scanning, and highlighting inspect the top frame only.

The selected search surface records a bounded possible page implementation marker when the page
exposes a recognized Google Programmable Search, Algolia, Elastic/App Search, Azure AI Search, Solr,
Typesense, Meilisearch, or Swiftype marker. After a run, the observed behavior fingerprint compares
result, zero-result, manual, and failed outcomes by category and operator. Result behavior alone is
not used to name a backend.

### Search reporting trace

Dork Suite and Site Search both create tracked Search sessions. Each generated task retains its
target, exact query, destination and dialect, dork ID and title, normalized operator IDs, catalog
review date, compatibility warnings, completion status, result count, and rendered result records
when collection succeeds. Site Search tasks additionally retain a sanitized snapshot of the
selected surface and bounded provider evidence, while DOM selectors and hidden form values stay
outside the report snapshot. Zero-result, failed, and manual-required outcomes remain in the trace.

Use `Report` to capture or snapshot the active target. Target-associated search sessions are then
included in Stakeholder HTML and JSON Evidence alongside the other correlated tester activity.
The report identifies Dork Suite versus Site Search, shows the exact submitted query and destination
context, and carries warnings or manual-completion reasons forward. JSON Evidence preserves the
full correlated search records and should be reviewed as potentially sensitive before sharing.

## Traffic ledger

The background service worker correlates `chrome.webRequest` lifecycle events and aggregates them
by method, origin, templated path, and query-parameter names. Each endpoint retains scope decision,
classification, observation counts, safe response metadata, confidence, reason codes, and every
factor contributing to its `0..100` priority score. The score ranks traffic for review; it is not
vulnerability severity.

The ledger never stores query values, URL credentials/fragments, header values, cookie values, or
raw request bodies. It keeps only sanitized header/body field names and allowlisted response
metadata. New `blanche.export` schema `1.1.0` payloads embed the ledger; Burp continues accepting
legacy exports without it. Runtime exports also declare retention limits, dropped/exported counts,
truncation, and coverage reason codes so downstream tools can distinguish a complete result from a
bounded subset. JSONL handoffs retain that envelope as an initial metadata record before the entry
records.

## Site tear sheet

The Report surface builds a per-site evidence package from the complete source browser capture and
the BLANCHE records that correlate to that site: findings, search tasks and results, documents,
Delivered JavaScript assessments and bounded startup coverage, latent-feature observations, and recent
activity. The Stakeholder mode translates that evidence
into an explainable tear sheet and masks raw captured values. JSON Evidence preserves the full
source capture and correlated records for technical review; it can include sensitive browser
storage values and should be stored and shared accordingly.

The tear sheet complements a HAR rather than replacing one. BLANCHE records browser-visible page,
frame, resource-timing, DOM, storage, worker, cache, runtime, and provenance data, but it does not
record complete raw HTTP transactions, header values, or response bodies.

By default, Burp Bridge will first POST the finished export to `http://blanche.invalid/ingest`. The OSINT Seed module will POST seeds to `http://blanche.invalid/osint/seed`. When the browser is proxied through Burp, the Burp extension consumes those synthetic requests directly inside the proxy flow. If the primary handoff fails, the Chromium side falls back to loopback endpoints under `http://127.0.0.1:47625/api/blanche/...`. The default uses the reserved `.invalid` TLD to reduce the chance of simple-hostname proxy bypass. Endpoints can still be changed or disabled in module settings.

## OSINT Orchestrator

Build the local CLI:

```powershell
npm run build:osint
```

Manual usage examples:

```powershell
node .\osint-orchestrator\dist\cli.js --target example.com --output-dir .\tmp\osint
node .\osint-orchestrator\dist\cli.js --seed-file .\seed.json --output-dir .\tmp\osint
```

Current passive collectors:
- public DNS
- public HTTP surface resources
- public TLS certificate metadata
- optional passive wrappers for `subfinder`, `assetfinder`, `amass`, `gau`, and `waybackurls`

AI-assisted analysis status:
- implemented now as normalized narrative generation and report-ready summarization inside the CLI output
- no live external LLM dependency is required yet

## Burp extension

The Burp-side project is scaffolded under [`burp-extension`](./burp-extension).

Current status:
- `BlancheBurpExtension` registers a `BLANCHE` suite tab.
- The tab accepts automatic JSON POST ingestion from the Chromium extension on:
  - `http://blanche.invalid/ingest`
  - `http://blanche.invalid/osint/seed`
  - `http://blanche.invalid/osint/report`
- The Burp extension also exposes loopback ingest bridges under `http://127.0.0.1:47625/api/blanche/...`, and the Chromium side will use them as automatic fallback paths if the proxy-native handoff fails.
- The tab can also still load a JSON export from disk and render:
  - summary
  - artifacts
  - storage
  - blob provenance
  - score-aware traffic ledger
  - raw JSON
  - OSINT seed
  - OSINT summary
  - OSINT findings
  - OSINT raw JSON
- Ingested pages are added to Burp's site map and highlighted in cyan when the export contains Chromium-only observations such as browser storage, Cache Storage, service worker state, blob/data URLs, or document-start instrumentation events.
- The Burp extension will also try to run the local OSINT CLI automatically when an OSINT seed arrives.

Build status:
- Build with:

  ```powershell
  npm run build:burp
  ```

  or:

  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\build-burp.ps1
  ```

## Checks run

```powershell
npm run typecheck
npm run test:console-disclosures
npm run test:target-requests
npm run test:traffic-ledger
npm run build
npm run build:osint
npm run build:burp
npm run smoke:target-url-controls
npm run smoke:tear-sheet
npm run smoke:burp-bridge
```

To smoke-test against a running Burp extension loopback listener instead of the built-in fake
receiver:

```powershell
$env:BLANCHE_SMOKE_EXTERNAL_INGEST_URL = "http://127.0.0.1:47625/api/blanche/ingest"
npm run smoke:burp-bridge
Remove-Item Env:BLANCHE_SMOKE_EXTERNAL_INGEST_URL
```

## Known limitations

- A site tear sheet is not a full HAR or packet capture. It does not contain complete raw HTTP
  request/response transactions, header values, or bodies.
- Traffic priority is deterministic triage metadata, not a finding or vulnerability severity.
- Scope policy activation controls automatic capture and follow-on actions; an unconfigured policy
  defaults to review and therefore authorizes neither.
- Stakeholder HTML masks raw captured values, but URLs, finding descriptions, and other contextual
  evidence may still be sensitive and should be reviewed before external distribution. JSON
  Evidence is intentionally fuller and may contain captured browser-storage values.
- Blob provenance is best-effort. Passive mode can observe existing blob URLs, but cannot retroactively prove how they were created.
- Instrumented mode captures document-start observations in frames where the content bridge and injected page script can run; it is not a universal provenance oracle.
- Dedicated/shared worker visibility is partial. Service worker registration metadata is stronger than generic worker enumeration.
- Cross-origin, restricted, browser-internal, and unsupported URLs still create visibility gaps and partial exports.
- Latent feature discovery does not guess unloaded chunks or endpoints. Bundle-only, runtime-only,
  signed, entitlement, and server-enforced candidates remain observation-only unless the page also
  exposes an unambiguous reversible browser-storage control. The switchboard changes local browser
  storage rather than delivered JavaScript bytes, and page diffs observed after a reload are not
  proof that the selected flag caused every change.
- Delivered JavaScript purpose and behavior results are bounded inferences. The startup action observes
  one startup reload without clicking, typing, submitting, replaying requests, or executing
  acquired source as extension code; unvisited and environment-dependent paths remain uncovered.
  Page-world event transport can be fabricated or suppressed by the inspected page and is retained
  as unverified evidence rather than per-script runtime proof.
- Burp highlights site map items for Chromium-only data using Burp's annotation API. Underlines and custom site map icons are not exposed here, so cyan highlighting is the implemented marker.
- The current OSINT narrative is heuristic/report-ready summarization. It is not a live LLM-backed analyst yet.
- External tool wrappers are best-effort and depend on those tools already being installed on the operator host.
- The Burp-side OSINT runner currently uses repo-local CLI discovery or `BLANCHE_OSINT_CLI`; a richer Burp-native settings UI is still pending.
- Search operators are constrained by each engine's index, ranking, market, and current parser.
  Documented syntax can still return incomplete results, and observed or fragile behavior can
  change. Review the catalog status and query preview before relying on a result.
- Site Search does not translate portable syntax into an arbitrary site's private query language.
  Saved selectors and routes can become stale, and login state, CAPTCHA, cross-origin restrictions,
  or site-side validation may leave a tracked task in a manual-required or failed state.
