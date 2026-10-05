# Score-Aware Traffic Ledger

BLANCHE records browser traffic as a bounded, privacy-preserving endpoint ledger. The ledger is
embedded in every new `blanche.export` document and can also be downloaded as canonical JSON or
newline-delimited metadata/entry records for downstream tools.

## Scope policy

An engagement profile owns one versioned scope policy. Activate the profile before automated
recon or active analysis. Each non-comment line in the in-scope, out-of-scope, or review editor
accepts an optional HTTP method followed by a matcher:

```text
example.com
*.example.com
POST https://api.example.com/v1/
10.20.0.0/16
```

Exact-host, wildcard-subdomain, and IPv4-CIDR matchers may add comma-separated scheme and port
constraints after the matcher:

```text
api.example.com schemes=https ports=443,8443
GET *.example.com schemes=https,wss ports=443,8443
POST 10.20.0.0/16 schemes=http,https ports=8080,8443
```

URL-prefix matchers already encode their scheme and port, so they do not accept those trailing
constraints. Existing policies are edited as structured rule rows. A save retains rule IDs,
priorities, sources, notes, grouped methods, dispositions, matcher kinds, and scheme/port
constraints. The three pattern editors bulk-add operator rules; each imported line receives a
generated rule ID, priority `100`, source `operator`, and no note.

Rules are evaluated by priority. At equal priority, exclusion wins, followed by review, then
inclusion. An unmatched endpoint receives the profile's explicit default disposition: `review`,
`unknown`, or `out-of-scope`. Scope is never inferred from ownership, and priority score never
changes scope.

Capture starts only from a directly in-scope request or an in-scope top-level tab. Once that target
is tracked, related first- and third-party requests are retained and each receives its own scope
decision. This preserves meaningful dependency and redirect boundaries without silently collecting
unrelated browsing. Automatic follow-on actions require an `in-scope` decision for their actual
destination. Manual operator actions remain explicit operator decisions.

Cross-origin redirect hops remain associated with the initiating target, but every hop keeps its
own disposition. An instrumented or reload export uses the session start as its retained-last-seen
window; a passive export uses the active top-level navigation start when that context is available,
which retains its cross-origin redirect hops without mixing prior tab incarnations. A request
completion alone never replaces the active page: BLANCHE changes context only after Chromium emits
a top-frame `webNavigation.onCommitted` event. Pending candidates and committed contexts share one
serialized browser-session record, so failed, overlapping, non-committing, and worker-interrupted
navigations cannot provisionally replace the last committed page. Passive queries also match the
committed context ID, not only tab, origin, or time. A short-lived committed-document marker lets
request events delivered on either side of the cross-API commit callback adopt the same context.
Because privacy templating can make distinct URLs look identical, URL-only navigation errors never
delete a candidate; exact request-ID errors or the bounded candidate TTL retire it.
Aggregated counts may include observations predating a requested window and declare
`OBSERVATION_COUNT_INCLUDES_PRE_WINDOW_HISTORY` when that occurs.

## Endpoint identity

The canonical endpoint identity is SHA-256 over:

```text
HTTP method
scheme
normalized host
effective port
templated path
sorted query parameter names
```

Numeric IDs, UUIDs, long hexadecimal values, high-entropy path tokens, and values following
sensitive path labels are templated. Query values, URL user information, and fragments are
discarded before storage. Method remains part of identity, so `GET /users/{int}` and
`POST /users/{int}` do not collapse into one entry.

Path templating is heuristic, not a proof that arbitrary path text is non-sensitive. Literal path
segments, query parameter names, and header/body field names can still reveal business semantics.
Downstream systems should apply their own handling policy to those names and use the declared path
model and coverage gaps when deciding whether an endpoint can be shared.

## Taxonomy

Each entry carries independently reviewable dimensions:

- Scope: disposition, policy ID/version, matched rules, basis, confidence, and reason codes.
- Boundary: same origin, same site, cross site, or unknown.
- Ownership: target, same organization, delegated, third party, shared, or unknown.
- Environment: production, staging, development, test, local, or unknown.
- Roles: navigation, API, authentication, authorization, administration, configuration, upload,
  download, realtime, telemetry, static, worker, client control, source map, or other.
- Access: anonymous, authenticated, privileged, service, or unknown.
- Operations: read, create, update, delete, authenticate, authorize, upload, download, subscribe,
  execute, or unknown.
- Data classes: credential, session, personal, financial, health, internal, and source code.
- Observation: timestamps, count, status codes, MIME types, resource types, cache state, byte
  counts, header/field names, evidence references, and explicit coverage gaps.

## Priority model

`blanche.traffic-priority.v1` is a deterministic triage score, not vulnerability severity.
Distinct factors are summed and clamped to `0..100`:

| Factor | Delta |
| --- | ---: |
| State-changing operation | +25 |
| Authentication or administration | +25 |
| Authorization, upload, privileged access, or sensitive data indicator | +20 |
| Configuration, realtime, client control, or source map | +15 |
| API, authenticated access, download, or cross-site boundary | +10 |
| Static asset or telemetry | -15 |

Bands are low `0-24`, medium `25-49`, high `50-74`, and urgent `75-100`. Every applied factor
retains its delta, reason, and evidence references. Downstream consumers should filter scope first,
then sort by score.

## Data handling

The traffic store is separate from the main host state, capped by entry count and serialized byte
budget, and persisted with debounced writes. It stores request/response header names and parsed
request-body field names only. Header values, body values, cookies, credentials, raw bodies,
query values, fragments, and URL user information are not retained. Safe response metadata is
limited to normalized MIME type, numeric length, status, and protocol.

The synthetic BLANCHE ingest endpoints are control-plane traffic and are excluded from application
traffic exports.

Every runtime export includes `metadata.captureCoverage`: the retained-entry and byte limits,
number of entries dropped by retention, entries available to the export query, entries actually
exported, a truncation flag, and machine-readable reason codes. Per-entry evidence/context caps are
also declared through `observation.coverageGaps`; consumers must not interpret an absent signal as
proof that it was absent on the wire.

Retention loss is labeled `store-wide-conservative`: its drop count and reason codes cover the
whole local traffic store and can include other target contexts. This can conservatively mark a
target export incomplete, but it cannot falsely claim completeness after a known store loss.
When persisted ledger state cannot be read, capture is disabled and
`PERSISTED_STATE_LOAD_FAILED` is written to independent local and browser-session coverage markers.
Marker writes use bounded retry, and either marker is restored on the next worker start. If every
available storage write fails, the current export reports `COVERAGE_MARKER_PERSIST_FAILED`; durable
reporting cannot be guaranteed while browser storage itself is unavailable.

## Downstream handoff

The canonical object is `trafficLedger` inside `blanche.export` schema `1.1.0`; the embedded ledger
uses kind `blanche.traffic-ledger` and schema `1.0.0`. The Burp tab accepts both legacy exports with
no ledger and new exports, and renders priority, scope, endpoint, classification, observations,
factors, and provenance.

For automated processing:

1. Reject unsupported schema major versions.
2. Select `scope.disposition === "in-scope"`.
3. Apply the required confidence or priority threshold.
4. Preserve `entryId`, policy version, score model, factors, and evidence references in derived
   records.
5. Inspect `metadata.captureCoverage.truncated` and every entry's coverage gaps before asserting
   inventory completeness.
6. Treat scores as routing/triage signals until a tester validates security impact.

JSONL begins with one `blanche.traffic-ledger.metadata` record containing the ledger metadata,
scope policy, summary, and data-handling contract. Each following
`blanche.traffic-ledger.entry` record carries the ledger ID and one endpoint entry. Consumers should
reject a stream whose metadata record is absent or unsupported.
