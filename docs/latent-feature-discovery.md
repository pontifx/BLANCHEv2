# Latent Feature Discovery

The `latent-features` Chromium module correlates client feature controls that were already shipped
to the browser. It does not enumerate endpoints, guess chunk names, bypass the browser cache, or
retry failed reads.

## Evidence sources

- `localStorage` and `sessionStorage`, including toggle values nested inside JSON containers
- known and flag-shaped bootstrap globals such as `__INITIAL_STATE__`, `__NEXT_DATA__`, and
  `__FEATURE_FLAGS__`
- feature-related DOM data attributes
- inline scripts already present in the current document
- script URLs already loaded by the current page
- flag-shaped JSON, configuration, and JavaScript responses already delivered through `fetch` or
  `XMLHttpRequest`

The runtime observer clones eligible responses after the page receives them and retains only
candidate summaries. It does not retain raw response bodies. Runtime observation has fixed
conservative response and byte budgets.

## Loaded-library reads

Loaded-library analysis is the only discovery path that can cause an HTTP cache lookup or request.
It is bounded as follows:

- only URLs already present in the page's script DOM or Resource Timing entries are eligible;
- third-party script origins are excluded by default;
- reads use `cache: "force-cache"` and never bypass the cache;
- passive source reads omit credentials, including for optional third-party libraries;
- failed reads are not retried;
- the default worker count is `1`;
- starts are globally spaced by `750 ms`, even when multiple workers are enabled;
- the default caps are `8` resources, `512 KiB` per resource, and `2 MiB` total;
- configured values are clamped to hard implementation limits, including at most `6` workers and
  at least `100 ms` between starts.

When a known dependency version is visible in a loaded script URL or source banner, BLANCHE can
check cached npm release metadata and the public OSV API. These lookups reuse the configured
library worker count and delay, have bounded timeouts, and cache assessments for 24 hours. The
default remains one worker and 750 ms spacing. Advisory lookup can be disabled in Labs.

`Auto-Discover On Navigation` is enabled by default. The bounded discovery action runs once per
completed top-level tab URL and can be disabled under Labs.

## Candidate model

Candidates retain:

- a stable normalized identifier;
- current, enabled, and disabled toggle values when observable;
- confidence;
- source/control surface;
- multiple evidence records for cross-source correlation;
- whether the candidate is a reversible browser-storage control.

A rescan compares stable candidate IDs for the same tab and origin. Candidate cards added by the
new delivery pulse once in the switchboard so an operator can distinguish a newly shipped or newly
reachable control from the previously reviewed set.

Hash-like key/value pairs are retained as opaque correlation evidence. BLANCHE does not attempt to
reverse or brute-force them.

Keys shaped like authentication, credentials, session identifiers, permissions, licensing, or
roles are excluded from local probing.

## Switching a local candidate

The workbench exposes explicit `ON` and `OFF` controls only for unambiguous, boolean-like values in
`localStorage` or `sessionStorage`. JSON-backed flags are updated at their exact stored path.

1. The current tab must still match the discovery tab and origin and be explicitly in scope.
2. BLANCHE compares the live value with the retained scan value and rejects a stale card.
3. Before the first write to a storage container, BLANCHE persists its complete original value.
4. It writes the selected ON/OFF value and optionally reloads the page once so startup gates can
   re-evaluate.
5. Additional reversible flags can be explored while the recovery record is active. Shared JSON
   containers keep a single original baseline.
6. `Restore All` writes each exact original container once and optionally reloads once.

The switchboard shows a highlighted virtual configuration diff; it does not patch delivered bundle
bytes. It also compares bounded top-frame DOM signatures before and after the switch, temporarily
highlights surviving changed elements, and labels the result *observed after toggle* because
unrelated reload or page activity can occur in the same interval.

The recovery record is persisted in extension host state so a service-worker restart does not
silently discard restoration information. Apply and restore require the exact tab and origin.

Runtime-response, runtime-global, DOM, bundle-only, and opaque-pair candidates remain observation
only because they do not expose a durable, reversible local control.

See [`feature-switchboard.md`](./feature-switchboard.md) for the interaction model, page/code
highlighting, recovery invariants, and deterministic local verification fixture.
