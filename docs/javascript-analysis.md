# JavaScript Analysis

BLANCHE JavaScript Analysis explains the likely purpose of JavaScript already delivered to the
current browser tab. It separates source transformation from behavior, retains the evidence behind
each conclusion, and gives the tester a bounded way to compare static evidence with one observed
page startup.

The analysis is triage. A transform label is not a vulnerability, a purpose score is not proof of
security impact, and a behavior that was not observed during one reload is not necessarily absent.

## Actions

### Analyze Current Tab

`Analyze Current Tab` performs bounded static source acquisition and analysis. It inventories inline
code and script URLs already reported by the document or Resource Timing. A tab that directly
displays JavaScript can also contribute the displayed response text. The action does not start a
runtime test, though already-retained attributable browser observations can support an assessment.
BLANCHE does not guess chunk names, enumerate nearby paths, brute-force source maps, or execute
acquired source as extension code.

Any additional script read is an anonymous `GET` evaluated by the active Traffic scope policy.
BLANCHE omits credentials, checks every visible redirect destination before following it, prefers
the browser cache, applies the configured delay and byte limits, and does not retry a failed read.
Third-party script origins are excluded by default. Metadata for an observed script may remain in
the report when policy or settings prevent its body from being read.

### Observe Startup: bounded startup observation

`Observe Startup (reloads)` is a bounded startup observation. It is available
only when the current HTTP(S) tab is explicitly `in-scope` under the active Traffic policy.

The action:

1. starts document-start instrumentation;
2. reloads the current tab exactly once;
3. waits for the top-level load within the collection timeout;
4. collects the same bounded static evidence plus runtime events and the windowed traffic recorded
   during that reload; and
5. records the result in a behavior matrix.

The action does not click, type into, or submit controls. It does not replay captured transactions,
change feature flags, mutate browser storage, guess inputs, follow application workflows, or test
candidate endpoints separately. The page can still perform its normal startup requests and state
changes during the reload. Those effects are recorded when visible.

The Traffic ledger and page-world event snapshots are frozen at the end of the configured startup
wait, before static page traversal and anonymous source reads. Those later reads cannot enter the
startup evidence window.

Each test cell has one of eight states:

| State | Meaning |
| --- | --- |
| `passed` | A collection control, such as bounded source acquisition or instrumentation startup, completed. |
| `observed` | Extension-owned evidence, such as the Traffic ledger, recorded the behavior during the reload. Artifact IDs are attached only to an extension-verified event whose initiator origin and path match the external script's final or source origin and path; query values and fragments do not participate in that comparison. |
| `observed-unverified` | Page-world instrumentation reported the behavior, but the same-window message transport can be fabricated or suppressed by page code. This state never raises an individual script to behavior maturity level `3`. |
| `static-only` | Source evidence supports the behavior, but no attributable runtime event was seen. |
| `blocked` | Scope, browser restrictions, an inaccessible frame, a failed read, or another recorded guardrail prevented the relevant observation. |
| `not-observed` | Neither sufficient static evidence nor an attributable runtime event was retained in this run. |
| `manual-required` | Completing the stage requires an operator-controlled workflow outside this one-reload action. |
| `failed` | The action attempted the stage and retained a failure reason. |

`not-observed` does not mean the behavior is absent. `blocked` identifies a known coverage gap
rather than a negative result.

The current document-start bridge labels page-world events `page-world-unverified`. These records
remain useful as leads and are retained with that provenance. BLANCHE does not turn them into
runtime feature candidates or attribute them to individual scripts. Traffic shapes independently
recorded by extension APIs are stored as `traffic-ledger-entry` evidence and may support an
`observed` page-level cell.

### Staged test plan

Each rubric result carries a four-stage plan so the evidence boundary remains visible:

| Stage | Mode | Meaning |
| ---: | --- | --- |
| `0` | `offline-static` | Analyze the bounded acquired text without executing it. This is the basis of `Analyze Current Tab`. |
| `1` | `isolated-sandbox` | Identify behavior that would require a separate disposable execution environment. The extension does not claim to provide that isolation or execute the acquired text as a standalone program. |
| `2` | `passive-observation` | Correlate behavior from an operator-driven in-scope scenario, including the bounded startup reload, without synthesizing requests or interacting with application controls. |
| `3` | `authorized-active` | Plan validation of a selected behavior at the server boundary under executable engagement scope, with explicit host, method, path, identity, rate, redirect, and state-change controls. The extension does not execute this stage. |

A stage is marked `ready`, `conditional`, `blocked`, or `complete`. The plan also records its
objective, allowed actions, success criteria, stop conditions, and a termination reason such as
missing source, an isolation requirement, missing runtime evidence, missing explicit scope, a
third-party active-test block, or required review of a state-changing behavior.

The startup action does not mean every plan stage is executed. It performs static source analysis
and one bounded runtime observation associated with stage `2`. Isolated execution, stage `3`
server-boundary validation, and interactive workflows remain separate or manual. The action never
implies exhaustive path execution.

## Purpose rubric

A script or group of correlated scripts can have one primary purpose, multiple secondary purposes,
and lower-scoring candidates. BLANCHE uses these normalized labels:

| Purpose | Typical evidence |
| --- | --- |
| `loader-runtime` | Module registries, chunk loaders, bootstrap wrappers, dependency startup, or polyfill setup. |
| `app-shell-ui` | Routing, rendered components, templates, view state, accessibility, or user-interface events. |
| `api-data` | API clients, serialization, response shaping, queries, schemas, or data synchronization. |
| `identity-access` | Sign-in state, tokens, account context, entitlements, permissions, or authorization gates. |
| `feature-configuration` | Feature flags, experiments, rollout rules, environment configuration, or variants. |
| `telemetry-analytics` | Metrics, traces, logging, crash reporting, advertising measurement, or product analytics. |
| `storage-offline` | Local storage, IndexedDB, Cache Storage, offline queues, or service-worker cache behavior. |
| `realtime-messaging` | WebSockets, event streams, push messaging, workers, shared workers, or background coordination. |
| `file-media-crypto-payment` | File processing, uploads/downloads, media pipelines, cryptography, encoding, checkout, or payment flows. |
| `developer-debug-admin` | Debug panels, test hooks, diagnostics, internal tools, administration, or privileged operator functions. |
| `third-party-integration` | A named external SDK or service integration whose function is distinguishable from the application shell. |
| `unknown` | Available evidence is too limited or contradictory to assign another purpose. |

Purpose points are attached to evidence records, not repeated keywords:

- attributable runtime behavior or matched source-map semantics: `+5`;
- a structural call or control-flow pattern: `+3`;
- a verified component or dependency signature: `+2`; and
- a relevant literal, route fragment, identifier, or selector: `+1`.

A primary purpose requires at least `7` points, independent evidence, and at least one strong item.
A secondary purpose requires at least `4` points. Lower-scoring supported labels remain candidates.
Repeating the same token inside one source does not create independent evidence.

## Transform labels

Transform labels describe representation and can be combined:

| Transform | Meaning |
| --- | --- |
| `readable` | Formatting and identifiers retain enough semantic structure for direct review. |
| `minified` | Whitespace and other nonessential syntax have been compacted. |
| `bundled` | Multiple modules or dependencies have been combined behind a loader or module registry. |
| `packed` | A wrapper decodes, expands, or reconstructs a payload at runtime. |
| `obfuscated` | Renaming, string indirection, encoded tables, control-flow changes, or similar transforms obscure intent. |
| `unknown` | The retained source is insufficient to classify its representation. |

Minification, bundling, and identifier mangling are common production build steps. Opacity is
reported separately from purpose, confidence, review priority, and security impact. It never adds
review-priority points by itself.

## Evidence and confidence

Every scored claim retains its evidence class, source label or URL, bounded supporting detail, and
whether the source was truncated. The normalized evidence classes are `content-metric`, `literal`,
`structural-pattern`, `component-signature`, `source-map`, and `runtime`.

- **High confidence** requires two independent evidence classes, including runtime, a matched source
  map, or structural flow, with no material coverage gap.
- **Medium confidence** requires one strong item or two corroborating static evidence classes.
- **Low confidence** is used for literal/signature evidence alone or materially limited coverage.

Truncation, a source-map mismatch, unresolved dynamic imports, unresolved decoders, or WebAssembly
limits confidence to medium. Uncertain source integrity limits confidence to low. A source-map
directive alone is not matched source-map evidence.

## Behavior maturity

Purpose and behavior maturity answer different questions. Purpose describes what the code appears
to do. Maturity records how far BLANCHE could trace a specific behavior axis in the retained
evidence.

| Level | Meaning |
| --- | --- |
| `0` | Not observed: no retained evidence supports the behavior in this run. |
| `1` | Reference/signature: a literal, identifier, route, selector, or component signature refers to the behavior. |
| `2` | Statically linked/reachable: calls or control flow connect the behavior to shipped code. |
| `3` | Runtime observed: an attributable event occurred during the instrumented reload. |

The matrix covers:

- `network`;
- `dom-ui`;
- `data-handling`;
- `identity-session-authorization`;
- `server-state-change`;
- `client-storage`;
- `dynamic-code-loading`;
- `persistence-background-realtime`;
- `cross-origin-transfer`; and
- `latent-debug-admin`.

A level `2` behavior can remain in the `static-only` observation state. Level `3` requires
extension-verified runtime attribution from the current bounded startup observation. BLANCHE
assigns level `3` only to an external script whose final or source origin and path match the event
initiator's origin and path; query values and fragments are ignored. Page-level stacks do not
identify individual inline scripts. The current same-window page-world
transport is explicitly unverified and therefore cannot produce level `3`. An old traffic entry or
unrelated page activity is not sufficient.

## Review priority

Review priority orders analyst follow-up. It is clamped to `0..100` and is not vulnerability
severity. BLANCHE records every contributing factor:

| Factor | Points |
| --- | ---: |
| Server-side state change | `+25` |
| Identity or access behavior | `+20` |
| Privileged, developer, or administration behavior | `+20` |
| Sensitive-data handling | `+15` |
| Dynamic or untrusted-code execution sink | `+15` |
| Cross-origin transfer | `+10` |
| Persistence or realtime/background behavior | `+10` |
| Debug, configuration, or latent-feature behavior | `+10` |
| Endpoint or origin fanout | `+5` |
| Verified vendor runtime only | `-15` |
| Telemetry only | `-10` |
| Static UI only | `-10` |

Reductions apply only when the retained evidence supports the limiting description. A high review
priority means the behavior deserves earlier human review; it does not establish exploitability or
impact. Scores below `25` are low, `25..49` are medium, `50..74` are high, and `75..100` are urgent.

## Acquisition and active-test scope

JavaScript that a site serves without authentication can be collected and reviewed as public
client-side evidence. That availability does not by itself authorize broader interaction with the
site.

`Analyze Current Tab` limits new traffic to bounded anonymous reads of already-observed script URLs,
and each read must pass the Traffic scope policy. Its acquisition is static-only: it does not reload
the tab or create a startup-observation run. Existing attributable runtime signals can still be
correlated when available. `Observe Startup (reloads)` adds a bounded startup observation. The reload can cause
the live page's normal startup requests, so the action requires an explicit `in-scope` decision for
the current tab before it starts. The one-reload constraint does not grant permission for additional
transactions or workflows.

An unconfigured policy, a `review` decision, and an `out-of-scope` decision authorize no automatic
read or bounded startup observation. Redirects do not inherit authorization from their starting
URL; every visible hop is evaluated separately.

## Collection caps

The relevant default and hard limits are:

| Surface | Default | Hard behavior |
| --- | --- | --- |
| Direct JavaScript document text | Up to `524,288` characters | Text beyond the cap is marked truncated. |
| Inline scripts | Up to `20`, `65,536` characters each | Additional or longer inline text is not retained. |
| Page script/resource inventory | `1,000` script elements, `1,000` script URLs, `2,000` Resource Timing entries | Enumeration stops at each cap and records a warning. |
| Page globals and DOM signals | `2,000` window properties, `40` candidate globals, `500` DOM elements, `50` attributes per element | Enumeration is incremental and stops before eagerly materializing the remaining page surface. |
| Loaded script reads | `8` resources per analysis | Configured value is clamped to `1..100`. |
| Source per loaded script | `512 KiB` | Configured value is clamped to `16 KiB..4 MiB`. |
| Combined loaded source | `2 MiB` | Configured value is clamped to `64 KiB..16 MiB`. |
| Read concurrency | `1` worker | Configured value is clamped to `1..6`. |
| Read start spacing | `750 ms` | Configured value is clamped to `100..10,000 ms` and applies globally across workers. |
| Script request | One attempt with an `8 s` timeout | No retry; at most `10` visible redirect hops, with scope checked at every hop. |
| Correlated candidates | `200` | Configured value is clamped to `10..1,000`. |
| Rubric evidence records | `160` | Analysis option is clamped to a hard maximum of `500`. |
| Sanitized indicators | `80` | Analysis option is clamped to a hard maximum of `250`. |
| Purpose claims | `12` | Analysis option is clamped to a hard maximum of `32`. |
| Persisted script assessments | `64` per scan | Additional delivered source bodies are omitted with a scan warning. |
| Evidence snippet | `240` characters | Analysis option is clamped to a hard maximum of `500` characters. |
| Runtime response observation | Up to `40` eligible responses | Up to `32 KiB` per response and `512 KiB` combined; raw bodies are not retained by the observer. |
| Instrumentation history | Up to `400` recent events per instrumented frame | Older events are dropped from the in-page buffer. |
| Persisted startup evidence | Up to `200` sanitized records | Up to `50` extension-recorded Traffic ledger shapes are retained first, with the remaining space used for page-world events. Test-cell references resolve only to retained records. |
| Startup observation wait | `1,500 ms` | Configured value is clamped to `250..10,000 ms`; runtime and Traffic ledger snapshots close at this cutoff. |
| Bounded startup reload | Exactly `1` | Top-level load wait is limited to `15 s`; timeout is reported. |
| Bounded startup traffic handoff | Up to `1,000` scored ledger entries | Export metadata reports dropped, retained, and coverage information. |

`force-cache` is a cache preference, not a guarantee that no request occurs. Anonymous reads omit
credentials even when the inspected tab itself has an authenticated browser session. The bounded
startup reload uses the current tab's normal browser context, which is another reason it is treated
as an active action.

## Coverage limitations

The report explicitly carries collection warnings, blocked cells, truncation, and visibility gaps.
Material limits include:

- one startup reload covers only code reached during that page load;
- behaviors behind clicks, input, scroll, timers longer than the observation window, route changes,
  account state, entitlements, server flags, device capabilities, geography, or time may remain
  static or not observed;
- dynamic chunks are analyzed only after the page actually loads them; BLANCHE does not guess
  chunk names or unavailable endpoints;
- packed or obfuscated code can exceed parser and decoder visibility, and BLANCHE does not
  brute-force opaque values;
- WebAssembly behavior is opaque unless browser-visible imports, exports, or runtime effects expose
  supporting evidence;
- missing, mismatched, cross-origin, or truncated source maps limit semantic recovery;
- restricted pages, inaccessible frames, Content Security Policy, opaque responses, browser
  internals, and extension injection failures create known gaps;
- existing service workers and browser caches can reflect state created before instrumentation;
- page code can fabricate or suppress same-window instrumentation messages, so those events are
  labeled `page-world-unverified`, excluded from runtime feature candidates, and never raise an
  individual script to maturity level `3`;
- the runtime observer keeps candidate summaries rather than complete response bodies;
- the traffic ledger records safe endpoint shapes and response metadata rather than full raw
  requests, headers, credentials, bodies, or responses; and
- anti-analysis logic and environment-dependent code can behave differently under instrumentation.

Static evidence and runtime observation support follow-on review. They do not prove that every code
path was executed, that a behavior is reachable for every user, that a server accepted an action,
or that an apparent security control is enforced only in the browser.
