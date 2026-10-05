# BLANCHE analysis provenance and scoring

Run date: 2026-09-24

This note distinguishes core BLANCHE output from custom collection/extraction and subsequent
manual interpretation. A BLANCHE triage label or score is not a finding of security impact.

## Original public-JavaScript audit

The original runner compiles and calls BLANCHE's `analyzeScriptPurpose` implementation
(`run-blanche-analysis.mjs`, lines 10-13 and 37-39). For each retained source, the following
reported values originate in the BLANCHE result:

- artifact ID;
- transform primary/detected labels, confidence, complexity score, and source metrics;
- coverage gap codes;
- purpose category, confidence, and score; and
- the complete review-priority object, including model, score, band, and factors.

The runner creates the surrounding `blanche.public-javascript-audit` envelope, collection claims,
HTTP metadata, hashes, and Vantage authentication-surface fields. Its `extractEnvironmentMappings`
regex is custom runner code (lines 164-186), not a BLANCHE classifier. `environmentIndicators` is
also a custom DEV/SIT substring filter (lines 208-213) over host indicators first extracted and
sanitized by BLANCHE. The runner's attempted `coverage.sourceIntegrity` projection (line 199) does
not correspond to a field in the current `ScriptAnalysisCoverage` interface, so JSON serialization
omits it.

The runner supplies no source-map or runtime observations—only a scope object (lines 75-95). Its
results are therefore static lexical/structural triage. The scope string `ownership:
"first-party"` is runner-supplied and is not one of the current `ScriptOwnership` union values;
it does not enter the review-priority calculation.

## Core analysis order

`analyzeScriptPurpose` performs these operations in order
(`scriptPurposeAnalyzer.ts`, lines 96-135):

1. source metrics;
2. any caller-supplied runtime evidence;
3. transform classification and transform complexity;
4. indicator extraction;
5. coverage assessment;
6. purpose scoring;
7. behavior maturity;
8. review-priority scoring.

Thus transform complexity is computed before indicator extraction. Purpose scoring occurs after
indicator extraction but independently scans the source and does not consume the indicator list.
Behavior analysis consumes host indicators for cross-origin evidence. Review priority is last and
uses purpose claims, behavior maturity, and host indicators. The runner's environment mapping,
Webpack map, route, and component extraction occurs after BLANCHE analysis and cannot influence
any BLANCHE score.

## Transform and purpose formulas

Minification is detected when any of these is true (`scriptPurposeAnalyzer.ts`, lines 189-196):

- longest line is at least 1,000 characters;
- mean non-empty line length is at least 420; or
- source is at least 2,000 characters with a whitespace ratio no greater than 0.055.

Transform precedence is obfuscated, packed, bundled, minified, readable, unknown (lines
1113-1117). Base complexity is 80, 70, 45, 25, or 0 respectively. The final complexity score is:

```text
clamp_0_100(max(base complexity, largest matched transform-rule weight)
            + min(20, max(0, matched signal count - 1) * 4))
```

For MVP2, minification metrics plus the Webpack signature produce `bundled` + `minified` and a
complexity score of 49: bundled base 45 plus one four-point secondary-signal uplift. This is a
representation score, not review priority or vulnerability severity.

Purpose rules contribute one match per rule: runtime or matched source-map evidence +5,
structural patterns +3, component signatures +2, and literals +1. A primary purpose needs score
at least 7, a match worth at least 3, and at least two evidence classes. A secondary purpose needs
score at least 4 (`scriptPurposeAnalyzer.ts`, lines 313-399;
`scriptPurposeRubric.ts`, lines 407-498 and 553-559). Claim confidence is high only with at least
two evidence classes including runtime, source-map, or structural evidence; score at least 4 or
one such strong class gives medium otherwise, subject to coverage downgrades
(`scriptPurposeAnalyzer.ts`, lines 1019-1031).

MVP2's `loader-runtime` score of 5 is the +2 loader signature and +3 dynamic script-loading rule.
The original runner omits the claim's BLANCHE `role`; in the full result it is secondary, not
primary, because 5 is below 7.

## Review-priority formula

Review priority uses the model `blanche.script-review-priority.v1`. Base weights are defined at
`scriptPurposeRubric.ts`, lines 561-574. A behavior factor is multiplied by maturity and rounded:

```text
maturity 0 = 0; maturity 1 = 0.25; maturity 2 = 0.67; maturity 3 = 1.00
score = clamp_0_100(round(sum(applied factor weights)))
```

Maturity multiplication is implemented at `scriptPurposeAnalyzer.ts`, lines 1206-1209. Host
fanout adds a factor only with at least three extracted hosts. Vendor-only, telemetry-only, and
static-UI-only evidence can subtract points (`scriptPurposeAnalyzer.ts`, lines 698-801). Bands are
low below 25, medium 25-49, high 50-74, and urgent 75-100.

MVP2's reported review priority 14 is BLANCHE-derived:

- dynamic loading, maturity 2: round(15 x 0.67) = 10;
- cross-origin reference, maturity 1: round(10 x 0.25) = 3; and
- network fanout, network maturity 1: round(5 x 0.25) = 1.

The score explicitly has `isVulnerabilitySeverity: false`.

## Latent-candidate provenance and boolean limitations

The follow-up runners call BLANCHE's separate `analyzeLatentFeatures` implementation. Candidate
keys, normalized IDs, current/suggested/enabled/disabled values, confidence, control surface,
probeability, and evidence originate in that analyzer. It emits categorical confidence—not a
numeric score.

For bundle text, BLANCHE assigns:

- high confidence to recognized feature-provider calls;
- medium confidence to flag-shaped storage references;
- high confidence to object boolean pairs whose key looks flag-shaped, otherwise medium when
  nearby text supplies feature context;
- medium confidence to flag-shaped assignments; and
- low confidence to opaque hash pairs.

These rules are at `analyzer.ts`, lines 340-463. Correlation keeps the strongest categorical
confidence, and sorting prefers probeable controls, then confidence, evidence count, and key
(`analyzer.ts`, lines 590-627). This confidence measures pattern fit, not the probability that a
value is a real product feature or is reachable.

`parseToggleValue` mechanically maps `false`/`!1` to disabled and `true`/`!0` to enabled
(`analyzer.ts`, lines 482-542). It cannot understand negated property semantics, reducer lifecycle,
server overrides, entitlements, or whether a component is mounted. Consequently:

- `disabled:false` can be labeled a high-confidence toggle-shaped candidate even though its
  ordinary meaning is that a control is enabled;
- `perusal:false` and `isPerusal:false` are not themselves proof that Perusal is OFF for a given
  user; in the shell they are initial user-mode state later replaced through reducers/profile
  data. Follow-up cross-bundle tracing nevertheless demonstrates that the resulting value is a
  real business-mode gate in production MFE consumers; and
- `defaultIsVisible:false` establishes a hidden-by-default component property, not that the
  component is mounted, reachable, privileged, or tied to a route.

Neither `perusal` nor `defaultIsVisible` appears in either machine-generated latent-candidate JSON
artifact. They were found and interpreted during manual context review. The custom feature-map
runner's `explicitOffCandidates` grouping is also not a BLANCHE judgment: it simply tests JSON
equality between `currentValue` and `disabledValue` (lines 130-135 and 594-595). In this run that
group contained only `disabled:false`, which manual review rejected as a product feature gate.

Bundle-only candidates are observation-only. BLANCHE permits ON/OFF switching only when a
boolean-like candidate is tied to an exact, unambiguous `localStorage` or `sessionStorage` path
(`docs/feature-switchboard.md`, lines 8-18).

## Custom extraction and manual triage

The following were produced by custom runner regexes, not core BLANCHE scoring:

- Webpack public path and chunk ID/hash manifests;
- startup/deferred chunk grouping;
- Module Federation environment maps and activation references;
- remote component bindings;
- React route definitions and relevant route literals;
- exact-toggle-expression tables; and
- the `explicitOffCandidates`/`referenceOnlyCandidates` groupings.

The following are analyst conclusions based on source context rather than BLANCHE labels:

- `perusal` is server-controlled profile/reducer state and, after following it into public
  production MFE consumers, a demonstrated business-mode gate. Terms-of-use controls, contact
  mutation controls, and account-setting mutation controls are disabled or guarded when it is
  true, although the reviewed coverage is not a universal page lock. This conclusion is manual
  dataflow analysis, not BLANCHE candidate scoring;
- authentication status, server-provided layouts, entitlements, and user state choose the observed
  flows;
- compatibility paths that render empty elements are not switched-off feature evidence; and
- the DockMonitor definition is latent debug code hidden by default, but its mounting or
  reachability was not established.
