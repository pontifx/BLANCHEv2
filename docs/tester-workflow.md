# Tester Workflow

BLANCHE's regular workflow is intentionally small:

1. Open the side panel on an in-scope target.
2. Review the selected URL/parameters/GET/POST representation in `[01 Target / Output]`; copy only
   the representation needed for the next tool.
3. Open `Traffic`, save the authorized scope rules, and activate the engagement profile.
4. Choose `[02 Run Search]` or `View Documents`.
5. Watch live status, answer evidence-derived question cards, and move reportable items through
   Findings.

## Primary navigation

- **Home**: visible target/output transformation, the two start actions, live task status, open
  questions, and newest findings.
- **Search**: advanced query composition plus persisted task/result detail and throttles.
- **Findings**: scored tester output across search, documents, libraries, archives, and client
  features.
- **Traffic**: active scope policy, sanitized endpoint ledger, transparent priority factors, and
  JSON/JSONL handoff.
- **Documents**: the in-memory review queue, per-file download approval, sessions, and queue rules.
- **Report**: stakeholder tear sheet and complete JSON evidence for the latest site capture.
- **Labs**: Feed, Delivered JavaScript and Latent Features, Interest Model, module configuration,
  raw exports, and logs.

The navigation order follows increasing information and configuration depth. Scope still must be
configured before active testing; visual position does not broaden authorization.

## Scope and traffic

Scope profiles use structured rows for stable rule identity, provenance, priority, disposition,
matcher, grouped methods, constraints, and notes. Bulk-added patterns accept exact hosts, wildcard
subdomains, URL prefixes, IPv4 CIDRs, optional HTTP-method prefixes, and scheme/port constraints.
Exclude wins an equal-priority conflict. Unmatched traffic receives the profile's configured
`review`, `unknown`, or `out-of-scope` default.

The Traffic table is method-aware and sorted by deterministic priority. Filter to `in-scope`
before handing entries to active tooling; then select the score/confidence threshold appropriate
for the workflow. A high or urgent score identifies operationally significant traffic for review,
not a confirmed vulnerability.

`Observe Startup (reloads)` is an active Labs action because a normal page reload can cause startup
traffic and state changes. It is available only when the current HTTP(S) tab has an explicit
`in-scope` decision. An unconfigured policy, `review`, `unknown`, or `out-of-scope` decision does
not pass this gate.

The JSON and JSONL outputs omit URL/query/header/body values. Keep entry IDs, policy version,
score factors, and evidence references attached when deriving work queues or findings.

## Default advanced search

The home action builds one bounded recipe for the current target. It covers public footprint,
indexed files, archives, JavaScript/source maps, known libraries, URL/endpoint terms,
infrastructure/certificates, and client feature/experiment terms. Search work defaults to one
thread. Same-engine starts and identical-query repeats both default to 300 ms.

Task states distinguish `completed-results`, `completed-no-results`, `manual-required`, and
`failed`. A human-verification page is not silently treated as success; BLANCHE shows its exact
query and provides Copy and Open controls.

## Findings and questions

Findings retain a score, severity, host, summary, and direct evidence. A high score can create a
side-panel question only when the question can name the artifact or matched terms that caused it.
Answering a question marks the linked finding reviewed, reportable, or dismissed. Technical probe
controls remain in Labs.

For Delivered JavaScript, a transform label states how the source is represented. The rubric's
review-priority score orders analyst attention. Finding severity is a separate workbench field, and
validated vulnerability severity still requires evidence of reachability, impact, and server-side
behavior.

## Documents

Automatic capture means bounded, credential-free in-memory inspection, not filesystem download.
Metadata is queued only for an in-scope document or a document observed from an in-scope target
tab, and automatic body retrieval requires the document itself to be in scope. The queue records
why an item was retained, its score, hashes, interesting keyword counts, extracted URLs, and
container/compression signals.

Filesystem downloads require explicit tester approval. The optional rule setting uses its score
threshold and keyword list to promote documents for review; it never starts a browser download.

## Delivered JavaScript and latent-feature checks

`Analyze Current Tab` applies a versioned purpose rubric to bounded inline source, script URLs the
page already loaded, and browser-rendered source when the tab directly displays a raw `.js` or
`.mjs` document. It labels readable, minified, bundled, packed, and obfuscated transforms
separately from likely purpose, behavior maturity, confidence, coverage, and review priority.

Additional script reads prefer the cache and apply fixed caps. Defaults are one worker, 750 ms
between starts, eight scripts, 512 KiB per script, and 2 MiB per scan. Reads omit credentials,
require an `in-scope` Traffic decision for every URL and visible redirect hop, and are not retried.
Known versions can be compared with npm metadata and public OSV advisories using a 24-hour cache.

`Observe Startup (reloads)` performs one instrumented reload and correlates static claims with bounded
startup runtime events for network requests, DOM changes, storage writes, route changes, workers,
realtime connections, and runtime failures. It does not interact with controls, replay requests,
or execute acquired source as extension code. A static or not-observed result does not establish
absence: interaction paths, account and entitlement branches, delayed behavior, dynamic chunks,
and inaccessible frames can remain uncovered. Page-world instrumentation uses an untrusted
same-window transport, so its events are labeled `page-world-unverified` and cannot raise an
individual script to runtime maturity. Extension-recorded Traffic ledger shapes remain separate.

Feature controls are separated into reversible browser-storage candidates and evidence-only
bundle/runtime/hash candidates. The Feature Switchboard exposes ON/OFF only for an exact,
unambiguous browser-storage path. It checks the live value, stores the exact original container,
supports several local changes under one recovery record, optionally reloads once per action, and
restores every original container with `Restore All`. The highlighted source view is a virtual
configuration diff rather than a patch to loaded code. Page changes are bounded and labelled
*observed after toggle*, not causal.

See [`javascript-analysis.md`](./javascript-analysis.md) for the rubric, staged test plan and startup behavior matrix,
scope rules, collection limits, and coverage limitations.
See [`feature-switchboard.md`](./feature-switchboard.md) for switch, flash, diff, and recovery
semantics.
