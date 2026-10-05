# Vantage JavaScript hash-map and latent-feature review

Run date: 2026-09-24

## Collection boundary

- Anonymous reads only from `https://wellsoffice.ceo.wellsfargo.com`.
- No credentials, form submissions, storage changes, feature toggles, or startup interaction.
- No DEV or SIT host was requested.
- BLANCHE initially retained 19 production shell sources totaling 925,836 bytes. A later
  read-only follow-up requested publicly readable production MFE entries/chunks to trace the
  `perusal` value into its consumers; no application value was changed.

## Webpack maps

The main `MVP2` runtime contains 1,009 ordinary numeric chunk-ID to 20-hex-hash entries plus one special bundle entry, for 1,010 reconstructed JavaScript paths. Its public path is `/ceosignon/`:

```text
https://wellsoffice.ceo.wellsfargo.com/ceosignon/{id}.chunk.{hash}.js
https://wellsoffice.ceo.wellsfargo.com/ceosignon/49039.bundle.2b0106e70cb987448e2e.js
```

The runtime also contains five CSS entries using:

```text
https://wellsoffice.ceo.wellsfargo.com/ceosignon/{id}.bundle.{hash}.css
```

The entry module requests 22 IDs. Five are virtual Module Federation consume IDs and 17 resolve to production JavaScript files. The remaining 993 mapped entries are deferred, lazy, or unused on this startup path—not 993 proven disabled features. A 944-entry Pioneer icon context explains most of the large map.

The complete reconstructed path table is retained in `blanche-feature-map-audit.json`.

## Resolved feature/module keys

| Configuration or scope key | Resolved feature/component | Production resource |
| --- | --- | --- |
| `WFRIA_MFE_LOGINMFE` / `loginMFE` | `VantageLoginPXP`, `CAASLoginPXP`, `VantageInterdictionPXP` | `https://ciam.ceo.wellsfargo.com/login-mfe/auth/v1/remoteEntry.js` |
| `MFE_BD17B383_88CD_47E3_9EEF_6EEF5845F57F` / `tokenMFE` | `RSATokenPXP` | `https://ciam.ceo.wellsfargo.com/ciam/token-mfe/remoteEntry.js` |
| `MFE_679F4BFF_B2E1_4F90_BF96_BA6533C9FECE` / `svMFE` | `SVPagePXP` (OTP/SV) | `https://ciam.ceo.wellsfargo.com/ciam/otp-mfe/remoteEntry.js` |
| `MFE_CF086EC8_FF36_45EC_9A9C_F233469A99E0` / `consentMFE` | `ConsentPXP` | `https://ciam.ceo.wellsfargo.com/ciam/consent-mfe/remoteEntry.js` |
| `WFRIA_MFE_PWCMFE` / `pwcMFE` | `PWCPagePXP` (password change) | `https://ciam.ceo.wellsfargo.com/pwc-mfe/auth/v1/remoteEntry.js` |
| `MFE_C87ED3F2_2D6A_46C3_A875_C9BBFCC17C9F` | `AccountUnlockRemotePXP` / auth hub | `https://ciam.ceo.wellsfargo.com/ciam/auth-hub/remoteEntry.js` |
| `MFE_A4ED76E5_C005_4F9F_A664_CFFD3134C6A6` | `VantageAccountUnlockPXP` | `https://ciam.ceo.wellsfargo.com/ciam/accountunlock-mfe/remoteEntry.js` |
| `MFE_18199B69_86C2_4DD9_9D77_B264C110A5B2` | `NewUserContactInfo` | `https://wellsceomfes.ceo.wellsfargo.com/userprofilemanagementmfe/remoteEntry.js` |
| `MFE_5F757533_72B3_4D1A_BDE2_3D59E432BE10` | `MainContent` for terms of use | `https://wellsceomfes.ceo.wellsfargo.com/termsofusemfe/remoteEntry.js` |
| `CEOPT_MFE_FOOTERMFE` | `./Footermfe` | `https://wellsceomfes.ceo.wellsfargo.com/footermfe/footermfe/v1/remoteEntry.js` |
| `SELF_HELP_MFE` / `MFE_6DFC4560_E6F2_478F_8D95_E33063EDA3B5` | Self-help configuration | `https://wellsceomfes.ceo.wellsfargo.com/selfhelpmfe/selfhelpmfe/remoteEntry.js` |

The small MVP2 bootstrap retains an alternate `WFRIA_MFE_LOGINMFE` production URL under `wellsceomfes.ceo.wellsfargo.com`; the startup application chunk's active authentication-layout table uses the `ciam.ceo.wellsfargo.com` production URL shown above.

## Authentication-driven feature selection

These branches are selected by runtime authentication response state, not static on/off flags:

| Runtime condition | Selected layout/component |
| --- | --- |
| Default | `VantageLoginPXP` |
| `CAAS_CONSENT_REQUIRED` and `CAAS_BROWSER_OIDC` | `ConsentPXP` |
| `SV_REQUIRED`, or one MFA option equal to `SV` | `SVPagePXP` |
| `RSA_REQUIRED`, or one MFA option equal to `RSA` | `RSATokenPXP` |
| Multiple MFA options | `VantageInterdictionPXP` |
| `MUST_CHANGE_PASWRD_REQUIRED` or `PASWRD_CHANGE_RECOMMENDED` | `PWCPagePXP` |
| `#/oauth/login`, CAAS browser OIDC, and no `authStatus` | `CAASLoginPXP` |

Account-unlock and new-user layouts are additionally correlated with a server-provided PXP layout response and entitlements. Static source cannot establish their effective rollout state for a particular user.

## Reconstructed client routes

| Route key | Path | Static interpretation |
| --- | --- | --- |
| `Home` | empty/root path | Main sign-on surface |
| `ForgotPassword` | `/forgotPassword` | Forgot/reset-password flow |
| `NewUserSetUp` | `/newuser` | New-user setup router |
| `NewUserProfile` | `newuser/profile` | New-user contact/profile MFE |
| `NewUserTermsOfUse` | `/newuser/termsofuse` | Terms-of-use MFE |
| `OpenVantage` | `/ceosignon/openvantage` | Empty compatibility/no-op element in this build |
| `CeoSignOnRoot` | `/ceosignon` | Empty compatibility/no-op element in this build |
| `CeoSignOnNested` | `/ceosignon/*` | Empty compatibility/no-op element in this build |
| `OpenVantageHtml` | `/openvantage.html` | Empty compatibility/no-op element in this build |
| `Redirect` | `*` | Redirects to `/` |

Related hash-route evidence includes `#/oauth/login`, `#/newuser/profile`, and `#/newuser/termsofuse`. Relevant same-origin service literals include:

- `/portal/service/newUser/newUserStatus`
- `/portal/uaservice/up/presignon/getPageLoadObject`
- `/portal/service/shared/getUserInfo`

These strings establish shipped routing/configuration only; they do not prove anonymous reachability or authorization behavior.

## What is actually switched off?

BLANCHE's generic latent analyzer returned one apparent off candidate, `disabled:false`. Manual evidence review rejects it as a product feature gate: the matches are ordinary UI component defaults and HTML attribute metadata, and `disabled:false` means the controls are enabled.

One stronger off-like artifact is shipped:

- A Redux DevTools `DockMonitor`/`LogMonitor` definition uses `defaultIsVisible:false`, with visibility and position hotkey properties embedded in the code. The startup bundle executes the factory module but discards its exported component; static review did not establish that the monitor is mounted, store-connected, or reachable. Treat it as latent debug code, not a verified enabled debug console.

The follow-up trace materially changes the interpretation of `perusal`:

- `/portal/service/newUser/newUserStatus` supplies `perusal` in its response payload.
- The shell writes it to `newUserReducer.userProfile.perusal`, then publishes both the profile
  and `isPerusal` through the shared MFE host provider.
- The Terms-of-Use MFE reads the host profile value and disables the Accept and Decline radio
  buttons and the Continue button while it is true.
- The user-contact flow propagates it to its application store. The reviewed consumers disable
  Verify Number, Remove Phone, Edit Save, and New-user Save & Continue, and guard submit/confirm
  paths while it is true.
- The account-settings flow uses it to disable Automatic Access changes, E-sign consent, and the
  confirmation action for disabling SSO.

`perusal:false` is still only the initial fallback, not proof of the effective value for a user.
But `perusal` itself is now demonstrated to be a real server-controlled business-mode gate,
consistent with read/perusal-only behavior. Its UI coverage is incomplete: reviewed Edit/input,
Change Password, and primary SSO-anchor paths are not all directly gated. That semantic
classification comes from manual cross-bundle dataflow review; BLANCHE's lexical latent-feature
analyzer did not identify it.

Other false/off-like values remain state or presentation defaults:

- `disableForm:true` is the sign-on reducer's initial state and can be replaced by the page-load response.
- `showPlatformText:false` is a mobile-banner presentation option.
- Several `disabled:false` component props mean enabled controls.

Conclusion: the delivered code does not expose a conventional named rollout flag table, but it
does expose at least one consequential boolean business mode: `perusal`. Effective availability
is otherwise driven by authentication status, server-returned layouts, entitlements, and user
state.
