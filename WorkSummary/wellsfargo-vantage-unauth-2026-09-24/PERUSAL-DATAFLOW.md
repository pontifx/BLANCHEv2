# `perusal` / `isPerusal` production dataflow

Date inspected: 2026-09-24. Scope was passive review of anonymously retrievable **production** JavaScript already linked by the Vantage shell and its production remotes. No request was sent to DEV/SIT, no authenticated workflow was used, and no state-changing request or toggle attempt was made.

Offsets below are zero-based character offsets in the UTF-8-decoded, minified response. SHA-256 hashes are over the original response bytes.

## Result

`perusal` is not evidenced as a client-selected feature flag or an authorization bypass. In the new-user flow it is a server-returned user/session property:

```text
GET /portal/service/newUser/newUserStatus?RC=...&flowId=...
  -> response.data.perusal
  -> newUserReducer.userProfile.perusal
  -> shell HostProvider userProfile.perusal (and duplicate isPerusal state)
  -> Terms/User Profile remotes
  -> nested User Contact / User Account Settings remotes
  -> local setIsPerusal actions
  -> disabled controls and guarded handlers
```

The client has static `false` defaults, but the effective value is overwritten by response/host data. No route decision in the inspected shell uses `perusal`; it changes actions inside already-selected Terms, Contact/Profile, and Account Settings views. Static JavaScript establishes UI behavior only, not service-side authorization.

## 1. Source and shell propagation

### Shell request and response field

Source: [`69453.chunk.36716f8b5afaaf4be835.js`](https://wellsoffice.ceo.wellsfargo.com/ceosignon/69453.chunk.36716f8b5afaaf4be835.js)  
SHA-256 `93ceba75ca3e98410dcaf8f1340b2cc362c12c567183243de9b15fa7a4e252b8`; module `27597` starts near offset 387.

- Offset 12,899 constructs `{RC:n,flowId:r}` from URL query parameters.
- Offset 13,216 dispatches the successful response as `payload:a.data` under action type `GET_VANTAGE_NEW_USER_TYPE_AND_STEP` (constant at 53,199 in module `38682`).
- Endpoint `/portal/service/newUser/newUserStatus` is at 56,088 in module `56623`; module `31437` performs `GET` with the object as query params.
- Offset 13,726 sends the reducer's whole `userProfile` into the host provider.
- Offset 13,837 separately calls `addIsPerusal(p.perusal)`.

### Redux response mapping

Source: [`90460.chunk.6fd8af48bf6f8fcdcfb0.js`](https://wellsoffice.ceo.wellsfargo.com/ceosignon/90460.chunk.6fd8af48bf6f8fcdcfb0.js)  
SHA-256 `d928d319ae197612c561ac1d00af00a86b3dad82602761153515232a183ba679`; module `80288` starts near offset 75.

- Initial `newUserReducer.userProfile` is `{}` at 4,000; there is no reducer-level `perusal` default here.
- `case n.h8` starts at 4,731. At 4,845 it constructs `userProfile:{perusal:r.payload.perusal,cid:r.payload.companyId,uid:r.payload.userId}`.
- A separate later `GET_USER_PROFILE` case (`n.p6`, 5,940) replaces the entire object with `payload.data.viewProfileInfoResponse` at 6,369. The retained code does not prove whether that later response contains `perusal`.

### Host state and actions

In the shell chunk above:

- Host initial state at 50,055 is `userProfile:{cid:"",uid:"",perusal:false}` and has a second top-level `isPerusal:false` at 50,129.
- `addUserProfileAction` replaces `userProfile`; `addIsPerusalAction` starts at 50,343 and assigns its payload at 50,378.
- The dispatch facade exposes `addIsPerusal` at 50,708.
- On first render, the new-user reducer's `{}` can replace the host's nominal profile default and `p.perusal` can therefore propagate `undefined`. Downstream remotes use `...perusal || false`, so a missing/falsey value renders the non-perusal UI until a truthy server-derived value is present.

### Route relation

The new-user component chooses routes from `userType` and `returningUserStep`, not `perusal`:

- `/newuser/termsofuse` literals at 13,998 and 14,160.
- `/newuser/profile` literal at 14,079.
- `Normal`, `SSO`, `REGULAR_NEW_USER`, and `PDP` are the route conditions. No `perusal` conditional surrounds these navigations.

## 2. Terms-of-use consumer

Source: [`15208.bundle.b2581fcf9159471308e7.js`](https://wellsceomfes.ceo.wellsfargo.com/termsofusemfe/MFE_5F757533_72B3_4D1A_BDE2_3D59E432BE10/assets/js/15208.bundle.b2581fcf9159471308e7.js)  
SHA-256 `d1912fcade1f48f5b709f766c87780b56206b8ac2e1552c8b2604004ac33ce53`; slice module `7508`, UI module `12204`.

Dataflow:

- Slice default `isPerusal:false` at 1,541.
- `setIsPerusal` reducer at 1,565 assigns the action payload at 1,610; exported action alias is at 2,382.
- The wrapper reads `HostProvider.state.userProfile.perusal || false` at 9,626/9,645, passes it as `isPerusal`, and dispatches the local action in an effect at 9,429.
- Main content reads local `r.isPerusal` at 5,189/5,193.

Consequences:

- Accept radio: `disabled:w||!D` at 8,443.
- Decline radio: the same condition at 8,961.
- Here `D` means the terms content has been scrolled to the bottom, so the radios are disabled by either perusal mode or incomplete scrolling.
- Continue: `disabled:w` at 9,223.
- Terms text itself remains rendered.
- Form submit begins at 6,263 and dispatches `{termOfUseAccepted:true|false}` at 6,406/6,449. It has no separate `isPerusal` guard; the explicit perusal control in this chunk is the disabled UI.

The content/submit/user-info URLs are `/ceopub/content/legal/terms_of_use/terms_first_time_user.html`, `/termsofuseservice/newUser/recordTOUResponse` (9,890), and `/portal/service/shared/getUserInfo` (9,970). None is a perusal-specific lookup and none writes `isPerusal`.

## 3. User Profile -> User Contact Details propagation

### Edit profile

Source: [`99973.bundle.1992235788cd8e6760cc.js`](https://wellsceomfes.ceo.wellsfargo.com/userprofilemanagementmfe/MFE_18199B69_86C2_4DD9_9D77_B264C110A5B2/assets/js/99973.bundle.1992235788cd8e6760cc.js)  
SHA-256 `01b4437791b28bcede0d5ab92761f72665ba465c6347df3e0a0c38c916291e7d`.

- Module `48712` reads `HostProvider.state.userProfile`, then `l.perusal || false` at 2,946.
- At 3,418 it passes `isPerusal` to production child component `EditPanelFocusPageContent` in the `APP_CEOPT_USERCONTACTDETAILSMFE` remote.
- Generic loader module `56203` receives/passes the prop at 4,091/4,891.
- Exposure module `99973` maps `editProfile` to `EditProfileLayout` and `newUser/profile` to `NewUserContactInfo` near 10,800.

### New-user profile

Source: [`99548.bundle.99e16da2476ce8fec9ba.js`](https://wellsceomfes.ceo.wellsfargo.com/userprofilemanagementmfe/MFE_18199B69_86C2_4DD9_9D77_B264C110A5B2/assets/js/99548.bundle.99e16da2476ce8fec9ba.js)  
SHA-256 `e0bc020828275fe52a4c87daeedf8f35b7e3ff23246e0254ec0db093d5574956`; module `99548` starts near 1,483.

- Reads `host userProfile?.perusal || false` at 4,243.
- Propagates `isPerusal` through its wrapper at 3,595/3,690 and to child component `NewUserContact` at 3,339/4,581.

The child exposure is [`99973.bundle.c5d627961201c4d3e781.js`](https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/99973.bundle.c5d627961201c4d3e781.js), SHA-256 `77fb2a3a10df7c703995e8a30cea8e815f9aaa575b2bd985bd739c5b3a28cc6c`. It exports `EditPanelFocusPageContent`, `NewUserContact`, and `MainContent` and loads the chunks below.

## 4. User Contact Details local state and consequences

### Local action/reducer

Source: [`90627.bundle.774396b5bb79244ed884.js`](https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/90627.bundle.774396b5bb79244ed884.js)  
SHA-256 `d755a91a111e238014200bb4a1add6e802cfcbbec453bbe5c8016b755908d073`; module `3339` starts at 132.

- `app.isPerusal:false` default at 493.
- `setIsPerusal` reducer at 596; `e.isPerusal=n.payload` at 623.
- Export alias `fo` is `setIsPerusal` at 1,051-1,058.
- Its `fetchUserInfo` thunk writes `userData`, not `isPerusal`. Incoming perusal state is supplied by the parent prop/effect.

### Edit panel

Source: [`27366.bundle.36afe6c51807064f254b.js`](https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/27366.bundle.36afe6c51807064f254b.js)  
SHA-256 `f901c83db33d4c091beea667e346c31596e506a78726c12580db3386ec899621`; module `27366` starts near 480.

- Wrapper receives the prop at 9,773 and dispatches `setIsPerusal` (`B.fo`) at 10,253.
- Save button reads local state at 2,775 and is `disabled:l` at 3,466.
- Form submit reads local state at 7,263 and uses `e.preventDefault(),H||(...)` at 7,639: truthy perusal prevents the validation/save branch.
- The add-mobile confirmation path uses `H||dispatch(...)` at 9,588.

### Shared phone editor

Source: [`8188.bundle.3f645d3bf26bce6ce01c.js`](https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/8188.bundle.3f645d3bf26bce6ce01c.js)  
SHA-256 `ecf16f1307c9745be469dce37b222da17e6e3777c6777a733e9f79285a7b943b`; module `69667` starts near 10,978.

- Reads `app.isPerusal` at 18,872 and passes it to phone header/input components at 22,963 and 23,805.
- Remove-phone button is disabled at 13,632.
- Phone input uses `customValidators:v?[]:[...]` at 16,093, so perusal mode suppresses those custom validators. This is not evidence that every input is disabled.

### New-user contact

Source: [`59529.bundle.f9854a7c83595f543d6b.js`](https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/59529.bundle.f9854a7c83595f543d6b.js)  
SHA-256 `943527c7aee35c7fa32d24a519a04b12127d983a9db84c319261b85d0d87bebf`; module `59529` starts at 132.

- Wrapper receives `isPerusal` at 6,561 and dispatches `setIsPerusal` at 6,814.
- Main content reads `app.isPerusal` at 3,425.
- Save and Continue is `disabled:X` at 6,067.
- The form submit at 4,091 and confirmation callback at 6,418 do **not** contain an explicit perusal guard. The visible button is disabled, while the retained handler logic itself is unchanged.
- The add-phone button in this chunk is not disabled by perusal. The shared phone editor still disables removal and suppresses its custom validators as described above.

### Contact-details `MainContent`

Source: [`93253.bundle.b331dd6d031a63ff1275.js`](https://wellsceomfes.ceo.wellsfargo.com/usercontactdetailsmfe/APP_CEOPT_USERCONTACTDETAILSMFE/assets/js/93253.bundle.b331dd6d031a63ff1275.js)  
SHA-256 `860560eef3fd9b88249d9684223c004267b22ec715ec6523d012d5f2d13db9c0`; module `93253` starts near 8,999.

- The exported component receives `isPerusal` at 16,232 and dispatches `setIsPerusal` at 16,987.
- Phone verification reads local `app.isPerusal` at 13,760. Its click callback is guarded (`r || ...`) at 14,585 and the Verify button is disabled at 14,727.
- The Edit Profile anchor at 17,930 is not gated by `perusal` in this chunk; restrictions occur inside the edit panel.

## 5. User Account Settings propagation and consequences

### User Profile fan-out

Source: [`98173.bundle.21c426a014b1143ea774.js`](https://wellsceomfes.ceo.wellsfargo.com/userprofilemanagementmfe/MFE_18199B69_86C2_4DD9_9D77_B264C110A5B2/assets/js/98173.bundle.21c426a014b1143ea774.js)  
SHA-256 `db95e90944b27f42df55d4f5b7aeae7301ef835f3cf586bbfa9ed42bb9f8b452`; module `98173`.

- Reads `HostProvider.state.userProfile.perusal || false` at 8,214.
- Passes `isPerusal` to Contact Details at 6,876, Account Settings at 7,217, and Alert
  Preferences at 7,555. Alert Preferences was not followed further in this focused trace.

### Account local state

Source: [`45236.bundle.4cc2ec85192dfe378162.js`](https://wellsceomfes.ceo.wellsfargo.com/useraccountsettingsmfe/APP_CEOPT_USERACCOUNTSETTINGSMFE/assets/js/45236.bundle.4cc2ec85192dfe378162.js)  
SHA-256 `1ef285eef014b0e00b910fd129008c7cf5ea7060c31470f21d89bb905d78d9ac`; module `3339`.

- Defines `app.isPerusal:false` at 262 and `setIsPerusal` at 331; the reducer writes the
  payload at 358.
- Account wrapper module `83561` dispatches the received prop at 12,463.
- The standalone Auto Access wrapper in
  [`58815.bundle.69941a6616c07e61aa7c.js`](https://wellsceomfes.ceo.wellsfargo.com/useraccountsettingsmfe/APP_CEOPT_USERACCOUNTSETTINGSMFE/assets/js/58815.bundle.69941a6616c07e61aa7c.js)
  dispatches the same prop at 5,687.

### Account controls

Source: [`83561.bundle.24f5cda3cc34209fd608.js`](https://wellsceomfes.ceo.wellsfargo.com/useraccountsettingsmfe/APP_CEOPT_USERACCOUNTSETTINGSMFE/assets/js/83561.bundle.24f5cda3cc34209fd608.js)  
SHA-256 `0c769ba389d09a599e9e95661c359f501d82af6bad6c4dd4344d0353834add29`.

- The Automatic Access Enable/Disable button uses `disabled:isPerusal` at 3,316.
- The Disable SSO modal's **Yes** button uses `disabled:isPerusal` at 6,564; **No** remains
  available.
- At 11,393, perusal mode (or a missing/invalid URL) selects a disabled ordinary button instead
  of the actionable E-sign `AnchorButton`.
- Coverage is incomplete: the Change Password button at 9,320 and the primary SSO anchor near
  10,597 are not directly gated. Deactivation can open its confirmation modal, but the final
  **Yes** action is disabled.

## 6. Dormant/shared-library hits that should not be reported as active gates

- [`44985.chunk.bf313c4c1c1d334c6066.js`](https://wellsoffice.ceo.wellsfargo.com/ceosignon/44985.chunk.bf313c4c1c1d334c6066.js), SHA-256 `42b849607bed2eb749442a4b8598d1a9aabdec6b6e07a0c17aa46918277a0c2b`, contains a `perusalEvent` panel and a `userProfile.perusal && elementsToPeruse.length>0` condition near 20,783. That component is neither exported nor invoked from the shell path; the module exports only loader utility `Wr`, which the shell uses for cookie/adobe loaders.
- [`73470.chunk.73ca310b088b5115230c.js`](https://wellsoffice.ceo.wellsfargo.com/ceosignon/73470.chunk.73ca310b088b5115230c.js), SHA-256 `ff6c6862f5335ff289914291305f3888a3a1a584997c263fbdd159f126a9ec11`, contains the text `This functionality is not available in Perusal mode.` and a constructed `/portal/service/perusal/isPerusalMode` URL near 64,206. The warning component is not exported/invoked, and the URL is a discarded comma-expression value, not a request. The shell imports only exported utility `h3` from this module.

These are BLANCHE lexical hits, but treating them as reachable production behavior would be a false positive.

## Interpretation boundary

- **Evidence:** static `false` defaults, server response field `payload.perusal`, host-to-remote propagation, local reducer actions, disabled controls, and explicit client handler guards.
- **Not evidenced:** a client-side switch that grants access, a perusal-controlled route, a perusal-specific active lookup request, or backend authorization behavior.
- UI-only disabling should not be characterized as a security boundary. No service mutation was attempted, so this review makes no claim about what the server accepts or rejects.
