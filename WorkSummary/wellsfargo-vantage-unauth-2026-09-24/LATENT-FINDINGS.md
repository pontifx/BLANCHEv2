# Vantage unauthenticated latent-feature review

Run date: 2026-09-24

This review used anonymous GETs only against the public production sign-on origin. No
DEV/SIT host was contacted, no route was navigated, and no client-side value was changed.
Offsets below are zero-based JavaScript string offsets in the fetched response body.

## Defensible hidden-by-default control

Source: `https://wellsoffice.ceo.wellsfargo.com/ceosignon/69453.chunk.36716f8b5afaaf4be835.js`

- SHA-256: `93ceba75ca3e98410dcaf8f1340b2cc362c12c567183243de9b15fa7a4e252b8`
- Size: 58,005 bytes
- Offset 337: `defaultIsVisible:!1`
- Same component props: `toggleVisibilityKey:"ctrl-m"` and
  `changePositionKey:"ctrl-l"`

This is direct evidence of a keyboard-controlled UI component hidden by default. The
minified code identifies it only as module `10467`, so the evidence does not establish
the component's product name, its contents, an authentication bypass, or a URL.

Other false values in this chunk are ordinary state or presentation defaults rather
than latent auth features:

- Offset 36,080: smart-app-banner `darkMode:!1` default; the actual call overrides it
  with `darkMode:!0`.
- Offset 36,130: `disableCookies:!1`.
- Offset 36,148: `force:!1`.
- Offset 49,779: the actual banner call sets `showPlatformText:!1`.
- Offsets 50,082 and 50,129: initial `perusal:!1` and `isPerusal:!1`, later updated
  through reducers.

## Registered routes and state gates

The same active chunk registers these routes:

| Offset | Route key | Literal path |
| ---: | --- | --- |
| 48,405 | `Home` | `""` |
| 48,483 | `ForgotPassword` | `/forgotPassword` |
| 48,586 | `NewUserSetUp` | `/newuser` |
| 48,680 | `NewUserProfile` | `newuser/profile` |
| 48,784 | `NewUserTermsOfUse` | `/newuser/termsofuse` |
| 48,895 | `OpenVantage` | `/ceosignon/openvantage` |
| 49,006 | `CeoSignOnRoot` | `/ceosignon` |
| 49,107 | `CeoSignOnNested` | `/ceosignon/*` |
| 49,212 | `OpenVantageHtml` | `/openvantage.html` |
| 49,322 | `Redirect` | `*` |

The route literals are registered, so their presence is not evidence that they are
switched off. `OpenVantage`, `CeoSignOnRoot`, `CeoSignOnNested`, and
`OpenVantageHtml` render empty elements and appear to serve navigation/deep-link
handling.

Near offset 13,842, new-user navigation is conditional on server/runtime state:

- Types `Normal`, `SSO`, and `REGULAR_NEW_USER`: step 2/default redirects to
  `/newuser/termsofuse`; step 3 redirects to `/newuser/profile`.
- Type `PDP`: redirects to `/newuser/termsofuse`.

This is a workflow gate, not an off-by-default feature flag.

## Component/layout mappings

The active chunk contains these explicit layout-to-component mappings:

| Offset | Layout key | Component |
| ---: | --- | --- |
| 20,299 | `auth-hub-mfe` | `AccountUnlockRemotePXP` |
| 20,552 | `account-unlock-mfe` | `VantageAccountUnlockPXP` |
| 20,812 | `#/newuser/profile` | `NewUserContactInfo` |
| 21,077 | `#/newuser/termsofuse` | `MainContent` |

The `/forgotPassword` route renders an `ExperienceLayout` named `auth-hub-mfe`
near offset 10,271. No literal browser route for `account-unlock-mfe` is present in
this route table, so no path should be invented for it.

The corresponding production/non-production remote map is shipped in
`71297.chunk.b6989fb1b47c22488691.js` (SHA-256
`b9fdd191d0882aeaf70a91e596a4431e6db3283921ee191e0907bf4737714922`).
The relevant map keys begin at offsets 3,042 (auth hub), 3,501 (account unlock),
4,003 (new-user profile), and 4,655 (terms of use).

## Webpack hash maps versus feature maps

The large numeric-key maps in `MVP2` and `globals` are Webpack chunk-ID to
content-hash manifests. They assemble filenames of the form
`<chunk-id>.chunk.<content-hash>.js`; they do not map feature names to enabled or
disabled states.

`MVP2` starts its entry chunk expression at offset 317 and its resolver at offset
4,574. Its 16 app-specific manifest entries (relative to `globals`) are all loaded
either directly by the entry point or transitively through the declared shared-module
dependencies. Therefore, the manifest delta does not identify a switched-off feature.
The remaining shared-build manifest entries cannot safely be equated with disabled
features.

## BLANCHE candidate triage

The strict scan found no literal calls to common feature clients such as
`isFeatureEnabled`, `getFeatureFlag`, or `checkGate`, and no quoted opaque
hash-to-hash pairs.

Notable false positives were:

- `replace:!0` and `backgroundImage:!0` in the route chunk: router and theme props.
- `disabled:!1` or `enabled:!0` in design-system chunks: component defaults.
- `disabled:"disabled"` in React's HTML-property table.
- `legacyInterceptorReqResOrdering:!0`: an Axios compatibility option.
- `OTEL_SDK_DISABLED:!1`: telemetry is enabled, not disabled.
- bot/automation detection flags in the Splunk telemetry library: monitoring behavior,
  not Vantage product access controls.

The reducer bundle contains many workflow booleans (`disableForm`, `disableConfirm`,
feedback visibility, token-form visibility). They are modified by actions and represent
current UI state rather than shipped feature gates.

