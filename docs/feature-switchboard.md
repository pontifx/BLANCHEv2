# Feature Switchboard

The Feature Switchboard turns bounded Delivered JavaScript analysis into a reversible browser-side
experiment. It helps an authorized tester discover feature-shaped values, understand the retained
evidence for each one, and switch eligible local controls on or off without editing a minified
bundle by hand.

## What can be switched

A candidate is switchable only when BLANCHE correlates a boolean-like feature name with an exact
`localStorage` or `sessionStorage` location. Nested JSON values retain the storage key and complete
JSON path. Bundle-only, runtime-only, DOM-only, opaque, signed, entitlement, role, permission,
licensing, credential, authentication, and session-shaped candidates remain evidence only.

The switchboard never patches the JavaScript bytes that the page loaded. Its highlighted code view
is a virtual configuration diff showing the observed value and the value written to browser
storage. Packed, obfuscated, or truncated source can therefore supply a lead, but it does not
become executable extension code and it is not silently rewritten.

## Operator flow

1. Put the target page under an explicit in-scope Traffic policy.
2. Select **Analyze Current Tab**. Newly discovered candidates pulse once in the candidate list.
3. Review the candidate's confidence, evidence source, exact storage location, and ON/OFF values.
4. Select **ON** or **OFF**. BLANCHE rechecks the live stored value before writing so a stale scan
   cannot silently overwrite a page change.
5. BLANCHE saves the original storage container before an optional one-time reload. Additional
   candidates can be switched while that recovery record remains active.
6. Review the highlighted virtual code/config diff and the bounded page-structure changes observed
   after the switch. Changed or added elements pulse temporarily in the page; a surviving parent is
   used when a removed element cannot itself be highlighted.
7. Select **Restore All** to write every exact original storage container back and optionally reload
   once.

Page changes are labelled *observed after toggle*. Reloads, timers, network responses, and unrelated
page activity can change the DOM at the same time, so the diff is useful evidence rather than proof
of causation.

## Recovery and safety invariants

- Mutation and restore require the same tab and origin as the discovery or recovery record.
- A switch requires an explicit in-scope decision at execution time.
- Every first write to a storage container records its byte-for-byte original value before reload.
- Several flags can be explored in one session; shared JSON containers keep one recovery baseline
  and restore once, avoiding order-dependent rollback.
- Live value comparison rejects stale cards instead of overwriting a newer page value.
- DOM snapshots are top-frame, structural, selector-only, and capped. Form values, text bodies, and
  raw page HTML are not persisted in the page diff.
- Highlighting is temporary and respects reduced-motion preferences. A highlighting failure does
  not erase or misreport a storage mutation; the result remains applied with a warning and recovery
  stays available.
- The switchboard does not grant authorization, change server-side entitlements, bypass access
  control, submit forms, send messages, publish, purchase, or replay transactions.

## Verification fixture

The repository's Chromium workflow smoke test supplies deterministic local feature flags and a DOM
element gated by one of them. The acceptance path discovers an initially disabled flag, switches it
on and off, checks the live storage path and observed page diff, verifies new-candidate flashing,
and restores the original JSON container exactly. This fixture is preferred to a live site because
it is repeatable and cannot affect real accounts or production state.
