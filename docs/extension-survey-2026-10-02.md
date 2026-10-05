# BLANCHE extension survey and feature priorities

Research date: 2026-10-02. This is a product recommendation backed by catalog, documentation, repository, and local source review. The proposed features below have not been implemented or benchmarked in this turn.

BLANCHE's best opportunity is to make a browsing session reusable: preserve what was seen, extract useful facts, connect them to exact evidence, and let a human or an AI continue the same investigation without starting over. The highest-value features reduce repeated searching, copying, reformatting, tab management, and verification.

## Backup and review scope

The complete active `BLANCHE-main` project and workspace `AGENTS.md` were copied to [the full backup](../../backups/BLANCHE-full-pre-extension-survey-2026-10-02). Verification passed for **1,701 files / 4,530,860,152 bytes**: every source/backup pair matched in SHA-256 and size, no source file changed size or modification time during its copy, and the final source path inventory matched. Includes dependencies, compiled artifacts, work summaries, and saved Burp sessions. Historical `backups` and the older `blache-backup` copy were retained in place rather than duplicated. This is a local same-drive snapshot, not an independently stored disaster-recovery copy. Live browser-profile state outside this workspace is outside its scope. See [manifest](../../backups/BLANCHE-full-pre-extension-survey-2026-10-02/BACKUP_MANIFEST.txt), [per-file hashes](../../backups/BLANCHE-full-pre-extension-survey-2026-10-02/BACKUP_MANIFEST.json), and [reusable backup script](../../backups/backup-blanche-full.mjs).

The survey inventories **all 438 entries present in the observed public [Burp BApp Store catalog](https://portswigger.net/bappstore)**, with deeper documentation review of **45** selected extensions. This means complete coverage of that captured catalog page, not installation or runtime testing of 438 extensions, nor all historical/unlisted BApps. GitHub and general browser stores are sampled across relevant workflows; an exhaustive inventory of every extension on those open-ended platforms is not claimed.

The evidence directory is [research/2026-10-02-extension-survey](../../research/2026-10-02-extension-survey). It contains the full Burp CSV/JSON catalog, captured official detail pages, collector scripts, a coverage manifest, and separate browser and GitHub inventories. The browser sample covers **34 projects** across Chrome/Chromium, Firefox, Edge and Safari; the GitHub sample covers **23 repositories**, including extensions and supporting frameworks. Those samples overlap and must not be added as unique products. Browser availability and project capability are documentation claims, not verified installation results. Ratings, stars, marketing promises, and AI branding were not treated as proof of usefulness.

| Evidence set | Review coverage | Artifact |
|---|---|---|
| Burp BApp Store | 438 catalog entries; 45 selected official detail pages | [Full CSV](../../research/2026-10-02-extension-survey/burp/catalog.csv), [coverage manifest](../../research/2026-10-02-extension-survey/burp/coverage-manifest.json), [recommendations](../../research/2026-10-02-extension-survey/burp/findings.json) |
| Browser extensions | 34 projects; documented support separated from directly reviewed store listings | [Inventory](../../research/2026-10-02-extension-survey/browsers/inventory.json), [findings](../../research/2026-10-02-extension-survey/browsers/findings.md) |
| GitHub | 23 repositories; 5 supplementary official sources | [Inventory and recommendations](../../research/2026-10-02-extension-survey/github/github-inventory.json) |

## What BLANCHE already does

These observations come from the current local source and docs, not from a fresh live application test.

| Existing foundation | Evidence | Consequence for the roadmap |
|---|---|---|
| Search recipes, operator compatibility, query tracking, deduplication, and manual-required outcomes | [Search coordinator](../chromium-extension/src/background/searchCoordinator.ts), [architecture](architecture.md) | Extend the existing tracked workflow; another dork launcher adds little. |
| Document queue, SHA-256, extracted URLs, keyword scoring, explicit acquisition controls | [Document acquisition](../chromium-extension/src/modules/documentAcquisition/background.ts) | Add general page/table extraction and durable evidence, rather than duplicating file discovery. |
| Scoped, sanitized endpoint ledger with explained priority and coverage limits | [Traffic ledger](traffic-ledger.md) | Add evidence navigation, grouping, and action correlation; preserve the current redaction boundary. |
| Delivered JavaScript assessment, startup observation, feature switches with recovery | [JavaScript analysis](javascript-analysis.md), [feature switchboard](feature-switchboard.md) | Improve source-to-behavior navigation; a second generic JS scanner is lower value. |
| Versioned captures and observed/inferred/unavailable provenance | [Shared types](../shared-schema/src/types.ts) | Build on this vocabulary when adding citations and AI access. |
| One `lastExport` in host state; collection history trimmed to 25 sessions | [State store](../chromium-extension/src/background/stateStore.ts), [session manager](../chromium-extension/src/background/sessionManager.ts) | A durable multi-capture case store is a real addition. Existing exports on disk remain separate. |
| Finding evidence holds label/detail/optional URL; findings are bounded to 500 | [Finding model](../chromium-extension/src/shared/findingsWorkbench.ts), [manager](../chromium-extension/src/background/findingsManager.ts) | Add stable capture references and exact evidence anchors; a URL alone is not a historical citation. |
| Reports correlate by exact hostname and do not retain complete HTTP transactions | [Site tear sheet](site-tear-sheet.md) | Case-wide joins need explicit IDs. Exact request/response evidence must come from Burp or another explicit capture source. |

## Ranked features worth building

Priority is an engineering/product judgment, not a measured benchmark. P0 is the first useful release, P1 follows the evidence foundation, and P2 is specialized. Effort is relative to BLANCHE's current implementation: S is a contained feature, M crosses a few existing modules, L requires a new storage or execution subsystem.

| Rank | Proposed feature | Human payoff | AI payoff | Priority / effort |
|---|---|---|---|---|
| 1 | Save evidence once, find it later | Recover the exact page and reason it mattered after tabs close or content changes. | Retrieve stable, dated evidence without browsing again. | P0 / L |
| 2 | Highlight → cite → ask | Jump from every answer or note to the exact supporting passage. | Ground claims in explicit source spans and report missing support. | P0 / M |
| 3 | Copy a clean context packet | Select relevant tabs/evidence and send a concise, reviewed package to any AI. | Receive consistent Markdown/JSON with source IDs, coverage and redaction metadata. | P0 / M |
| 4 | Right-click an entity → investigate | Research a domain, email, IP, name, image or selected phrase without repeated copy/paste. | Use typed, scoped pivots with deterministic destinations and recorded results. | P0 / S–M |
| 5 | Point at a table/list → usable data | Extract a directory, results list or HTML table into editable rows. | Consume typed JSON/CSV with per-row citations rather than reparsing HTML. | P0 single page; P1 pagination / M |
| 6 | Reopen a case, not 60 anonymous tabs | Restore the useful tabs, notes, pending questions and next actions. | Continue from persisted task state and evidence IDs. | P1 / M |
| 7 | Show only meaningful changes | Compare versions while ignoring clocks, ads and random identifiers. | Re-evaluate only changed evidence and flag stale conclusions. | P1 / M |
| 8 | Show what happened after this click | Follow a UI action to related requests, response evidence and visible changes. | Diagnose workflows from a structured timeline with confidence limits. | P1 / L |
| 9 | Teach a short task once; resume it safely | Reuse a reviewed research/extraction workflow with checkpoints and takeover. | Execute bounded steps and return receipts instead of an opaque success message. | P1 / L |
| 10 | Decode, clean and copy in place | Unwrap URLs, decode text, pretty-print JSON, compare and export without switching tools. | Reuse deterministic transforms with original-to-derived lineage. | P0 / S–M |
| 11 | Turn shipped JavaScript into an evidence map | Locate the script, code excerpt, route or config behind a discovered behavior. | Separate static leads, observed behavior and untested possibilities. | P1 / M |
| 12 | Image/video verification workbench | Crop, extract keyframes, read metadata/OCR, and preserve search history together. | Work with frames, OCR spans and source timestamps that humans can inspect. | P2 / M–L |
| 13 | Small relationship views and a case timeline | See why two records may be connected without drowning in an automatic graph. | Traverse evidence-backed relationships and retain unresolved identities. | P1 / M |
| 14 | Coverage and contradiction board | Know what was checked, blocked, unanswered or contradicted. | Avoid treating zero results as absence or repeated copies as corroboration. | P1 / M |

### 1. Save evidence once, find it later

**Interaction:** one `Save to case` action captures the page, selected quote, metadata, screenshot where supported, and a readable derivative. Local full-text search finds it tomorrow. A case can hold several versions of the same URL.

**Documented precedents:** [SingleFile](https://github.com/gildas-lormeau/SingleFile) saves pages as self-contained HTML; [ArchiveWeb.page](https://archiveweb.page/) records browsed content for replay; [Hunchly's documented data model](https://support.hunch.ly/article/67-2-hunchly-data-forwarding) links captures, hashes, case metadata and extracted data. These are different preservation approaches, not interchangeable guarantees.

**BLANCHE delta:** add content-addressed storage and a durable case index alongside existing reports. Keep original bytes separate from reader text and summaries. Record capture method, time, final URL, MIME type, parent source and known omissions. MHTML is an available Chromium option via [pageCapture](https://developer.chrome.com/docs/extensions/reference/api/pageCapture); full interactive replay deserves a later Webrecorder integration rather than an unsupported completeness promise.

**Acceptance:** after a restart and a changed live page, a saved quote still opens its original capture. Modifying stored bytes is detected by hash verification. Failed or partial captures remain visibly partial. A content hash proves byte consistency, not the truth of the page or an independently attested capture time.

### 2. Highlight → cite → ask

**Interaction:** highlight a sentence, attach a question or note, and copy a source citation. Ask a question across selected evidence; each supported claim opens the exact original passage. Conflicting answers appear side by side.

**Documented precedents:** [Obsidian Web Clipper](https://github.com/obsidianmd/obsidian-clipper) provides highlights, local Markdown and templates; [Hypothesis](https://web.hypothes.is/) demonstrates annotations anchored to web content; [Zotero Connector](https://www.zotero.org/download/connectors) demonstrates collecting sources into an organized research library.

**BLANCHE delta:** upgrade `FindingEvidence` with capture ID, quote, quote context, position/selector where available, and derived-from references. Use the saved capture as the durable citation target; live DOM highlighting is a convenience that can fail independently. AI answers are interpretations layered above evidence.

**Acceptance:** every factual claim in an evidence answer either has a resolvable source anchor or is marked unsupported/inferred. Contradictory captures remain available. Clicking a citation selects the correct passage in a saved fixture even after the live DOM changes.

### 3. Copy a clean context packet

**Interaction:** choose `Send these 4 items to AI`, review the exact content and masked fields, and copy Markdown or JSON. The same clean reading view helps a person skim headings, tables and source passages without page clutter. A later local API lets approved clients query the same evidence objects instead of reading the whole case.

**Documented precedents:** [Playwright MCP](https://github.com/microsoft/playwright-mcp) supplies structured browser access; Burp's [MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc) connects Burp to AI clients; [Copy as Markdown](https://chromewebstore.google.com/detail/copy-as-markdown/fkeaekngjflipcockcnpobkpbbfbhmdn) reduces formatting work.

**BLANCHE delta:** produce a bounded envelope with case/evidence IDs, timestamps, sources, selected excerpts, missing coverage, redactions, and an item/byte budget. Default to selected content rather than the raw JSON Evidence export, which can contain storage values. Keep page text explicitly untrusted. A first release can be clipboard/file export; MCP or CLI is a later adapter, not a prerequisite for usefulness.

**Acceptance:** the same selection produces stable evidence IDs and deterministic redaction. A seeded credential does not appear in the packet. Removed data and omitted items are counted. Later API-adapter acceptance: a client can fetch one cited item without loading the entire history. Read and action capabilities are separate; exposing a localhost endpoint alone is not an authorization mechanism.

### 4. Right-click an entity → investigate

**Interaction:** select a domain or email and open a compact action menu: inspect occurrences in this case, derive appropriate search queries, look up public infrastructure, or record a lead. The menu previews the destination and the exact value to be sent.

**Documented precedents:** [Search by Image](https://github.com/dessant/search-by-image) streamlines image pivots; [SpiderFoot](https://github.com/smicallef/spiderfoot) demonstrates typed collection; Burp's [GAP](https://portswigger.net/bappstore/815bb4ab64e240618dc673d65016e919) gathers parameters and links from existing material.

**BLANCHE delta:** a shared entity normalizer and context menu above the existing OSINT seed/search scheduler. Preserve original and normalized values. Show only actions that fit the selected entity, scope and configured sources. Queue work in one place instead of opening a tab per provider immediately.

**Acceptance:** a domain selection needs no manual copy/paste and its query/result/source remain linked. Invalid or ambiguous selections require correction rather than silently choosing a type. Identical names are not automatically merged into one person.

### 5. Point at a table/list → usable data

**Interaction:** click a row, preview detected columns, rename them and export rows. Optional pagination shows a page/row cap and retains failed or incomplete pages.

**Documented precedents:** [Instant Data Scraper](https://chromewebstore.google.com/detail/instant-data-scraper/ofaokhiedipichpaobibbnahnkdoiiah) demonstrates point-and-extract workflows; Burp's [HTML Content Extractor](https://portswigger.net/bappstore/01c19fde30164b0aa112cf74befced53) applies CSS selectors; [Crawl4AI](https://github.com/unclecode/crawl4ai) and [Stagehand](https://github.com/browserbase/stagehand) document structured extraction approaches.

**BLANCHE delta:** generalize rendered search extraction into reviewed CSS/DOM extraction recipes with schema, preview, selector fallback and provenance. Each row needs a capture reference and an original cell value; normalized dates/numbers are derivatives. Do not assume that visually nearby content belongs to the same row.

**Acceptance:** a fixture with repeated headers, a missing field and two pages exports correctly without silent row loss. The AI can request `rows` with a defined schema. CSV values that spreadsheet software might execute are escaped safely in a spreadsheet-oriented export.

### 6. Reopen a case, not 60 anonymous tabs

**Interaction:** a case sidebar groups open tabs and saved pages by task, shows why each matters, and restores selected work with its notes and pending questions. One keyboard search spans tabs, history in the case, evidence, and commands.

**Documented precedents:** [Sidebery](https://github.com/mbnuqw/sidebery) provides tree-style tab management; [Tab Session Manager](https://github.com/sienori/Tab-Session-Manager) persists tab sessions. [Firefox Multi-Account Containers](https://github.com/mozilla/multi-account-containers) illustrates identity separation, but tab grouping does not provide that isolation.

**BLANCHE delta:** explicit case and task IDs across the current engagement profiles, searches, findings and exports. Restore tabs on demand and deduplicate by deliberate URL policy; do not collapse distinct authenticated or parameterized states just because hosts match. Chromium browser-profile separation and Firefox containers are different capabilities and should be labeled honestly.

**Acceptance:** restart midway through three search tasks; completed tasks stay completed, blocked tasks remain blocked, and the user sees the next uncompleted step. No blind replay of submissions or restoration of copied credentials.

### 7. Show only meaningful changes

**Interaction:** select the section or field to watch, compare two saved versions, and highlight relevant additions/removals. Ignore clocks, rotating recommendations or session values with visible rules. Start with manual comparison; recurring monitoring is a separate opt-in feature.

**Documented precedents:** [changedetection.io](https://github.com/dgtlmoon/changedetection.io) documents selectors and filters; [Distill](https://distill.io/) offers page monitoring; Burp's [Diff Last Response](https://portswigger.net/bappstore/902ef17f5aaa4f8eabe00491de3b241d) and [Sequence Comparer](https://portswigger.net/bappstore/fd75bc61c9364dab833a61312fdaa07d) demonstrate comparisons at different levels.

**BLANCHE delta:** versioned normalization recipes, raw/normalized diff toggles, and invalidation of claims based on changed evidence. Compare both human-visible content and selected structured fields. Keep presentation changes distinct from factual changes.

**Acceptance:** a date/address change is detected while a fixture's rotating banner is ignored; raw evidence still preserves both. A failed retrieval is labeled failed, never reported as unchanged or removed.

### 8. Show what happened after this click

**Interaction:** select a recorded UI action to see the surrounding DOM state, related requests, redirects, downloaded artifacts and visible outcome. Follow a request into Burp when full transaction evidence exists.

**Documented precedents:** [Logger++](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81) and [Flow](https://portswigger.net/bappstore/ee1c45f4cc084304b2af4b7e92c0a49d) organize traffic; [Playwright Trace Viewer](https://playwright.dev/docs/trace-viewer) connects recorded actions, page snapshots and network inspection. The proposed browser-to-Burp click bridge is a BLANCHE design inference, not a claim that these extensions already implement the whole feature.

**BLANCHE delta:** correlate browser action/session/document/frame IDs with ledger and Burp event references. Show exact and heuristic matches separately; timestamp proximity alone does not establish causation. Keep sanitized endpoint identity distinct from raw URL identity so two requests to the same shape are not falsely joined.

**Acceptance:** a test click and concurrent unrelated polling are both recorded, with the unrelated request not presented as proven causal traffic. Browser-visible evidence still works when Burp is absent; full payload claims do not.

### 9. Teach a short task once; resume it safely

**Interaction:** record a simple read/extract workflow, edit its steps, provide parameters, preview its effect and run it again. Stop at login, CAPTCHA, unexpected navigation or a consequential action; let the person continue and resume from the checkpoint.

**Documented precedents:** [Automa](https://github.com/AutomaApp/automa), [Selenium IDE](https://github.com/SeleniumHQ/selenium-ide), and [Stagehand](https://github.com/browserbase/stagehand) demonstrate reusable automation at different abstraction levels.

**BLANCHE delta:** extend tracked Search tasks into versioned recipes with preconditions, expected outcomes, time/step/URL budgets, idempotency rules and durable step receipts. AI can suggest a repair when a selector fails; a suggested repair is not permission to submit a different action.

**Acceptance:** interrupt a three-page extraction after page two; resume without duplicating results or resubmitting completed forms. Each step shows its observed result. No credential, spending, publishing, messaging or unapproved external write is implied by a recipe.

### 10. Decode, clean and copy in place

**Interaction:** select text or a captured message and apply URL/Base64 decoding, JSON formatting, date conversion, deduplication, diffing or a saved transform recipe. Copy the selected result as Markdown, JSON, CSV or a request template.

**Documented precedents:** [CyberChef](https://github.com/gchq/CyberChef) composes data operations; [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) supplies encoding/escaping transforms; [Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278) demonstrates format conversion.

**BLANCHE delta:** a small curated local transform palette, not embedding every operation at once. Save original input, transform version/parameters, and output reference. Extend existing target URL copy actions while continuing to label constructed requests as templates. Copying code never executes it.

**Acceptance:** reapplying a saved recipe to saved bytes reproduces the output. Lossy steps show a warning in the preview. Decoding a JWT is never described as signature verification. URL cleaning preserves the original and does not silently break signed URLs.

### 11. Turn shipped JavaScript into an evidence map

**Interaction:** click a discovered route/config/endpoint and see its source script, excerpt, content hash, associated runtime observations and whether it has actually been visited. Search across the delivered material using consistent filters.

**Documented precedents:** [JS Link Finder](https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf), [JS Miner](https://portswigger.net/bappstore/0ab7a94d8e11449daaf0fb387431225b), and [LinkFinder](https://github.com/GerbenJavado/LinkFinder) demonstrate static discovery.

**BLANCHE delta:** improve navigation and source spans around the existing analyzer rather than adding another score. Keep inferred routes separate from runtime observations; bundled strings do not prove a reachable page or permission. Source maps and external resources require explicit acquisition policy and coverage records.

**Acceptance:** every route lead opens the right retained source excerpt and hash. The UI and AI payload distinguish `found in source`, `observed in traffic`, and `unverified`. A missing source map is reported as unavailable.

### 12. Image/video verification workbench

**Interaction:** preserve the original media, create a crop or keyframe, extract OCR/metadata, and choose a reverse-search destination. Review related results and their dates without losing the original.

**Documented precedents:** [InVID/WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) groups media-verification tools; [Search by Image](https://github.com/dessant/search-by-image) supports image-based search workflows.

The InVID project documentation includes older release information, and the current Chrome listing could not be fetched in this survey. Its workflow is a useful reference; current installation and service operation remain unverified.

**BLANCHE delta:** link original media, crops, frames, OCR and translated text through explicit derivation records. Search results are leads with query dates, not proof of first publication. External uploads need clear destination/content previews. An AI-generated authenticity score should not substitute for evidence.

**Acceptance:** a saved frame resolves to its video time; OCR resolves to image coordinates. A reverse-search submission records exactly which derivative was sent. Unsupported/blocked media is retained as a limitation rather than silently omitted.

### 13. Small relationship views and a case timeline

**Interaction:** select an entity and see a small neighborhood of related sources, domains or documents with a readable reason for each connection. Toggle to a timeline showing publication, event and collection dates separately.

**Documented precedents:** [LinkScope Client](https://github.com/AccentuSoft/LinkScope_Client) provides entity/relationship analysis; [SpiderFoot](https://github.com/smicallef/spiderfoot) illustrates collecting related entities.

**BLANCHE delta:** make graph edges cite evidence IDs and relationship types such as `mentioned on`, `linked to`, or `shares identifier`. Keep analyst/AI hypotheses separate from observed connections; a shared service or analytics ID alone does not establish common ownership.

**Acceptance:** every edge explains its source. Two identical display names stay separate until explicitly resolved. Unknown date/timezone values remain unknown. Table/list views offer the same information without requiring a graph.

### 14. Coverage and contradiction board

**Interaction:** a case shows questions, checked sources, results, blocked attempts, duplicates, conflicting evidence and a short queue of useful next steps. The operator can see exactly why a suggested action might resolve an uncertainty.

**Documented precedents:** BLANCHE already records manual-required search outcomes, provenance and collection limits. Structured evidence/automation projects in the survey provide reusable status models. This combined board is a proposed synthesis, not a verified feature copied from a single extension.

**BLANCHE delta:** connect those states across the case; distinguish duplicate syndication from independent corroboration; separate priority, confidence, severity and coverage. Negative results need the actual query, source, time and limitations. Rank actions by expected contribution to a named question, not by the number of findings they might generate.

**Acceptance:** CAPTCHA, timeout, zero results and not-yet-tried remain distinct. A claim contradicted by a newer capture is visible to both the human and AI. An unanswered question cannot disappear merely because its source was evicted from a recent-history list.

## First release I would choose

Build one vertical workflow around a small durable case store: **select something → save evidence → extract/annotate → copy a cited context packet → reopen it tomorrow**. Include single-page table extraction, entity pivots and the small transform palette in that flow. This makes the application useful even without a model subscription or a new automation server.

Then add paginated collection, case restore and normalized comparisons. Introduce agent tool access only after evidence IDs, selection boundaries and read/action permissions are stable. Add click-to-request mapping and resumable recipes after those contracts exist. Media verification and broad graph analysis can follow without blocking the common text/data workflows.

Suggested shared records are `Case`, `Capture`, `EvidenceSpan`, `Entity`, `Claim`, `Task`, `ActionReceipt`, and `TransformRecipe`. The same records should render in the sidebar and serialize for automation. Put raw capture bytes in a dedicated bounded local store/optional local companion, with indexes and explicit retention/export behavior; do not keep expanding the single host-state object indefinitely. This is an architectural proposal, not a decided migration.

Integrate mature capture/replay, reader extraction, OCR and format-conversion components where licensing and platform fit permit. Build BLANCHE's case/evidence contract, workflow UX, provenance joins and permission boundary. The differentiation is the continuity between tools. Public repository availability does not itself grant permission to relicense or bundle its code.

## How to prove these features help

Use representative local fixtures and a small set of consented real workflows. Record a manual baseline before evaluating prototypes. Proposed acceptance targets below are not measured results:

1. Save a quote with a durable source citation in at most two deliberate actions from the selected text.
2. Find a known saved fact and its original page without reopening a search engine.
3. Extract a paginated table with no silent missing or duplicate rows; explicitly account for incomplete pages.
4. Answer a case question with every supported claim resolvable to the evidence; count unsupported claims separately.
5. Resume an interrupted task without repeating completed submissions or losing manual-required state.
6. Compare versions with a known substantive change and known noise; measure missed changes and false alerts separately.
7. Construct a context packet with a fixed budget and no seeded secrets; report included/omitted material accurately.

Measure task completion time, human interactions, duplicate visits, citation correctness, extraction error rate and AI input size. A feature that increases collected data but does not improve a measured task should not earn priority automatically.

## Lower-value directions for this request

- Another generic chatbot beside the page without exact-source citations and selected context.
- Another large dork menu, library version detector or opaque risk score, since BLANCHE already has useful foundations there.
- Auto-opening every OSINT provider or an unbounded crawler that creates review work faster than it resolves questions.
- A giant relationship graph with speculative identity merging or unsupported ownership claims.
- Exploit-specific scanners, bypass collections and attack payload generators as headline OSINT usability features. They solve a different testing problem; the transferable value is in their workflow, extraction, comparison and evidence handling.
- Treating a store listing, GitHub stars, a content hash, or the word AI as proof of reliability.

No app runtime code, dependencies, extension installs, external accounts, provider credentials, or scheduled jobs were changed by this survey. The delivered result is the verified backup, research inventories, this proposed feature roadmap, and a work-turn trace.
