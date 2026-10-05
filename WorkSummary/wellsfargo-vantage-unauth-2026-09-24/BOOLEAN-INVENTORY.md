# BLANCHE boolean/configuration inventory

Generated: 2026-09-24T19:15:30.999Z

## Scope and interpretation

This inventory statically parsed 31 anonymous production JavaScript sources (1,195,651 bytes): 19 retained Vantage shell sources, 6 directly exposed production feature-MFE chunks, and 6 production contact/account consumer chunks derived from their own public runtime maps. All 19 shell sources matched the SHA-256 recorded by the prior BLANCHE feature-map audit; fresh hashes are recorded for the MFE chunks. No form, credential, storage value, DEV/SIT host, or unlisted remote was accessed.

A literal `false` or `!1` is not, by itself, a disabled product feature. The inventory includes component defaults, reducer transitions, library options, property descriptors, and runtime bookkeeping. Use the classification and role fields as triage aids, then inspect the occurrence evidence in the JSON.

## Summary

| Measure | Count |
| --- | ---: |
| Boolean-like occurrences | 1336 |
| Unique exact keys | 331 |
| App/business-classified occurrences | 313 |
| Library/runtime-classified occurrences | 1023 |
| Keys observed as both true and false | 105 |
| Reducer/state-associated keys | 56 |
| Environment maps parsed from production files | 18 |
| Uppercase action/state/status tokens | 342 |
| Dynamic boolean-shaped bindings | 307 |
| Perusal-linked control bindings | 3 |
| Feature consumer guard expressions | 48 |
| Reviewed Vantage-owned occurrences | 357 |
| Reviewed Vantage-owned keys | 103 |
| Parser diagnostics | 0 |

## Reviewed Vantage-owned fields

This subset uses explicit reviewed module provenance (shell modules 80288 and 27597, the Terms/User-Profile application modules, and non-library modules in the six nested contact/account chunks). It avoids treating bundled Axios/React metadata as Vantage fields. The JSON still retains every raw occurrence and the broader heuristic classification.

| Key | Values | Count | Roles | Sources |
| --- | --- | ---: | --- | --- |
| `slim` | `true` | 16 | component-prop, state-or-option | `27366.bundle.36afe6c51807064f254b.js`<br>`58815.bundle.69941a6616c07e61aa7c.js`<br>`69453.chunk.36716f8b5afaaf4be835.js`<br>`8188.bundle.3f645d3bf26bce6ce01c.js`<br>`83561.bundle.24f5cda3cc34209fd608.js` |
| `status` | `false`, `true` | 11 | reducer-state, state-or-option | `45236.bundle.4cc2ec85192dfe378162.js`<br>`90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `border` | `true` | 10 | component-prop, state-or-option | `15208.bundle.b2581fcf9159471308e7.js`<br>`27366.bundle.36afe6c51807064f254b.js`<br>`69453.chunk.36716f8b5afaaf4be835.js`<br>`99973.bundle.1992235788cd8e6760cc.js` |
| `showError` | `false`, `true` | 9 | boolean-option, reducer-state | `45236.bundle.4cc2ec85192dfe378162.js`<br>`90627.bundle.774396b5bb79244ed884.js`<br>`99973.bundle.1992235788cd8e6760cc.js` |
| `showFeedback` | `false`, `true` | 9 | boolean-option, default, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `disableForm` | `false`, `true` | 8 | boolean-option, default, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `required` | `true` | 8 | state-or-option | `8188.bundle.3f645d3bf26bce6ce01c.js` |
| `decorative` | `true` | 7 | component-prop, state-or-option | `27366.bundle.36afe6c51807064f254b.js`<br>`58815.bundle.69941a6616c07e61aa7c.js`<br>`69453.chunk.36716f8b5afaaf4be835.js`<br>`8188.bundle.3f645d3bf26bce6ce01c.js`<br>`83561.bundle.24f5cda3cc34209fd608.js` |
| `isCountryCodesInProgress` | `false`, `true` | 7 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `isUnmaskedPhoneInProgress` | `false`, `true` | 7 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `show` | `false`, `true` | 7 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `disableConfirm` | `false`, `true` | 5 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isContactDataInProgress` | `false`, `true` | 5 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `showSuccess` | `false`, `true` | 5 | boolean-option, reducer-state | `45236.bundle.4cc2ec85192dfe378162.js`<br>`58815.bundle.69941a6616c07e61aa7c.js`<br>`83561.bundle.24f5cda3cc34209fd608.js` |
| `disableStepOneConfirm` | `false`, `true` | 4 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `disableStepThreeConfirm` | `false`, `true` | 4 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `enableFocusTrap` | `true` | 4 | boolean-option | `58815.bundle.69941a6616c07e61aa7c.js`<br>`8188.bundle.3f645d3bf26bce6ce01c.js`<br>`83561.bundle.24f5cda3cc34209fd608.js` |
| `isAlertPreferencesInProgress` | `false`, `true` | 4 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `isCsrfTokenInProgress` | `false`, `true` | 4 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `isEditProfileInfoInProgress` | `false`, `true` | 4 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `isfetchVerifyPhoneInfoInProgress` | `false`, `true` | 4 | reducer-state, state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `isIPhone` | `false`, `true` | 4 | boolean-option | `69453.chunk.36716f8b5afaaf4be835.js`<br>`90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isPerusal` | `false` | 5 | boolean-option, component-default, reducer-state | `15208.bundle.b2581fcf9159471308e7.js`<br>`45236.bundle.4cc2ec85192dfe378162.js`<br>`69453.chunk.36716f8b5afaaf4be835.js`<br>`90627.bundle.774396b5bb79244ed884.js` |
| `isRecordToUResponseInProgress` | `false`, `true` | 4 | boolean-option, reducer-state | `15208.bundle.b2581fcf9159471308e7.js` |
| `isSaveInProgress` | `false`, `true` | 4 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `isTermsOfUseContentInProgress` | `false`, `true` | 4 | boolean-option, reducer-state | `15208.bundle.b2581fcf9159471308e7.js` |
| `isValidateProfileInProgress` | `false`, `true` | 4 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `isvalidateSVCodeInProgress` | `false`, `true` | 4 | reducer-state, state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `replace` | `true` | 4 | component-prop | `69453.chunk.36716f8b5afaaf4be835.js` |
| `saveSuccess` | `false`, `true` | 4 | reducer-state, state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `validateError` | `false`, `true` | 4 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `withCredentials` | `true` | 4 | state-or-option | `69453.chunk.36716f8b5afaaf4be835.js`<br>`90627.bundle.774396b5bb79244ed884.js` |
| `alphaCheckMarkDisabled` | `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `createPasswordFailed` | `false`, `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isAddMobileMsgBoxOpen` | `false`, `true` | 3 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isAndroid` | `false`, `true` | 4 | boolean-option | `69453.chunk.36716f8b5afaaf4be835.js`<br>`90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isBypassSelected` | `false`, `true` | 3 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isEmpty` | `true` | 3 | boolean-option | `69453.chunk.36716f8b5afaaf4be835.js` |
| `isMobile` | `false`, `true` | 4 | boolean-option | `69453.chunk.36716f8b5afaaf4be835.js`<br>`90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isOpenSupportedCountryPanel` | `false`, `true` | 3 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `numCheckMarkDisabled` | `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `perusal` | `false` | 3 | default, reducer-state | `15208.bundle.b2581fcf9159471308e7.js`<br>`69453.chunk.36716f8b5afaaf4be835.js`<br>`99973.bundle.1992235788cd8e6760cc.js` |
| `profileSaving` | `false`, `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `pwdLengthCheckMarkDisabled` | `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSecureValidation` | `false`, `true` | 3 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `specialCharCheckMarkDisabled` | `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `systemError` | `false`, `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `updatingPassword` | `false`, `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `current` | `false`, `true` | 2 | state-or-option | `27366.bundle.36afe6c51807064f254b.js` |
| `darkMode` | `false`, `true` | 2 | component-default, component-prop | `69453.chunk.36716f8b5afaaf4be835.js` |
| `disableStepTwoConfirm` | `false`, `true` | 2 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `fullWidth` | `true` | 2 | state-or-option | `27366.bundle.36afe6c51807064f254b.js` |
| `index` | `true` | 2 | state-or-option | `99973.bundle.1992235788cd8e6760cc.js` |
| `isOpenConfirmationPanel` | `false`, `true` | 2 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isProfileDataChanged` | `false`, `true` | 2 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `phoneVerified` | `false`, `true` | 2 | reducer-state, state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `recordToUResponseError` | `true` | 2 | reducer-state | `15208.bundle.b2581fcf9159471308e7.js` |
| `showPlatformText` | `false`, `true` | 2 | boolean-option, component-default, component-prop | `69453.chunk.36716f8b5afaaf4be835.js` |
| `showSuccessConfirmation` | `false` | 2 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSv` | `false` | 2 | boolean-option, reducer-state, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSV` | `false`, `true` | 2 | boolean-option, reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `stacked` | `true` | 2 | component-prop | `69453.chunk.36716f8b5afaaf4be835.js` |
| `termOfUseAccepted` | `false`, `true` | 2 | state-or-option | `15208.bundle.b2581fcf9159471308e7.js` |
| `validatingToken` | `false`, `true` | 3 | reducer-state, state-or-option, switch-case-update | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `vcValidated` | `false`, `true` | 2 | reducer-state, state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `AAAuthorized` | `false` | 1 | state-or-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `authStatus` | `false` | 1 | state-or-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `backgroundImage` | `true` | 1 | component-prop | `69453.chunk.36716f8b5afaaf4be835.js` |
| `changePasswordSuccess` | `false` | 1 | state-or-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `deactivateStatus` | `false` | 1 | reducer-state | `45236.bundle.4cc2ec85192dfe378162.js` |
| `disabled` | `true` | 1 | state-or-option | `83561.bundle.24f5cda3cc34209fd608.js` |
| `disableDocumentTitleUpdate` | `true` | 1 | boolean-option | `83561.bundle.24f5cda3cc34209fd608.js` |
| `emailAsDefault` | `true` | 1 | state-or-option | `27366.bundle.36afe6c51807064f254b.js` |
| `eventMessagingAvailable` | `false` | 1 | state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `formValid` | `true` | 1 | state-or-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `fullScreen` | `true` | 1 | state-or-option | `27366.bundle.36afe6c51807064f254b.js` |
| `goToHomePage` | `false` | 1 | state-or-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isAccountSettingsSectionVisible` | `true` | 1 | boolean-option, reducer-state | `99973.bundle.1992235788cd8e6760cc.js` |
| `isAlertPreferencesSectionVisible` | `true` | 1 | boolean-option, reducer-state | `99973.bundle.1992235788cd8e6760cc.js` |
| `isContactDetailsSectionVisible` | `true` | 1 | boolean-option, reducer-state | `99973.bundle.1992235788cd8e6760cc.js` |
| `isExperienceDone` | `true` | 1 | boolean-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isLandline` | `true` | 1 | boolean-option | `8188.bundle.3f645d3bf26bce6ce01c.js` |
| `noIcon` | `true` | 1 | state-or-option | `83561.bundle.24f5cda3cc34209fd608.js` |
| `open` | `true` | 1 | state-or-option | `8188.bundle.3f645d3bf26bce6ce01c.js` |
| `openEditPanel` | `true` | 1 | state-or-option | `27366.bundle.36afe6c51807064f254b.js` |
| `otpValidated` | `false` | 1 | state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `resendSuccess` | `false` | 1 | state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `secure` | `true` | 1 | state-or-option | `69453.chunk.36716f8b5afaaf4be835.js` |
| `showErrorMsg` | `false` | 1 | boolean-option, reducer-state | `99973.bundle.1992235788cd8e6760cc.js` |
| `showHardTokenForm` | `false` | 1 | boolean-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showRsa` | `false` | 1 | boolean-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSoftTokenEnrolledForm` | `false` | 1 | boolean-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSuccessData` | `false` | 1 | boolean-option, reducer-state | `45236.bundle.4cc2ec85192dfe378162.js` |
| `step3InformationContainers` | `true` | 1 | state-or-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `TZAuthorized` | `false` | 1 | state-or-option | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `validateProfileError` | `true` | 1 | reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `validateSVCodeError` | `true` | 1 | reducer-state | `90627.bundle.774396b5bb79244ed884.js` |
| `validationAborted` | `false` | 1 | state-or-option | `90627.bundle.774396b5bb79244ed884.js` |
| `disableCookies` | `false` | 1 | boolean-option, component-default | `69453.chunk.36716f8b5afaaf4be835.js` |
| `force` | `false` | 1 | component-default | `69453.chunk.36716f8b5afaaf4be835.js` |

## Keys observed with both values

| Key | True | False | Classification |
| --- | ---: | ---: | --- |
| `__filtered__` | 1 | 1 | app 0 / library 2 |
| `_done` | 1 | 1 | app 0 / library 2 |
| `_ended` | 1 | 1 | app 0 / library 2 |
| `_running` | 2 | 1 | app 0 / library 3 |
| `[c]` | 1 | 1 | app 0 / library 2 |
| `active` | 3 | 4 | app 0 / library 7 |
| `allOwnKeys` | 6 | 3 | app 0 / library 9 |
| `Bi` | 1 | 1 | app 0 / library 2 |
| `configurable` | 95 | 10 | app 0 / library 105 |
| `connected_` | 1 | 2 | app 0 / library 3 |
| `createPasswordFailed` | 1 | 2 | app 3 / library 0 |
| `current` | 2 | 2 | app 2 / library 2 |
| `darkMode` | 1 | 1 | app 2 / library 0 |
| `decorative` | 8 | 1 | app 7 / library 2 |
| `defaultIsVisible` | 1 | 1 | app 0 / library 2 |
| `dependsOnOwnProps` | 1 | 1 | app 0 / library 2 |
| `disableConfirm` | 1 | 4 | app 5 / library 0 |
| `disabled` | 1 | 3 | app 1 / library 3 |
| `disableForm` | 4 | 4 | app 8 / library 0 |
| `disableStepOneConfirm` | 1 | 3 | app 4 / library 0 |
| `disableStepThreeConfirm` | 1 | 3 | app 4 / library 0 |
| `disableStepTwoConfirm` | 1 | 1 | app 2 / library 0 |
| `done` | 19 | 21 | app 2 / library 38 |
| `enumerable` | 81 | 34 | app 0 / library 115 |
| `error` | 2 | 4 | app 0 / library 6 |
| `escapeDeactivates` | 1 | 1 | app 0 / library 2 |
| `fired` | 1 | 1 | app 0 / library 2 |
| `fullScreen` | 1 | 1 | app 1 / library 1 |
| `hasError` | 1 | 1 | app 1 / library 1 |
| `hovered` | 1 | 2 | app 0 / library 3 |
| `invertTheme` | 1 | 2 | app 0 / library 3 |
| `isAddMobileMsgBoxOpen` | 1 | 2 | app 3 / library 0 |
| `isAlertPreferencesInProgress` | 1 | 3 | app 4 / library 0 |
| `isAndroid` | 1 | 3 | app 3 / library 1 |
| `isBypassSelected` | 1 | 2 | app 3 / library 0 |
| `isCaptchaPlayerLoaded` | 1 | 1 | app 0 / library 2 |
| `isContactDataInProgress` | 1 | 4 | app 5 / library 0 |
| `isCountryCodesInProgress` | 2 | 5 | app 7 / library 0 |
| `isCsrfTokenInProgress` | 1 | 3 | app 4 / library 0 |
| `isDimHidden` | 1 | 1 | app 0 / library 2 |
| `isEditProfileInfoInProgress` | 1 | 3 | app 4 / library 0 |
| `isfetchVerifyPhoneInfoInProgress` | 1 | 3 | app 4 / library 0 |
| `isIPhone` | 1 | 3 | app 4 / library 0 |
| `isMobile` | 2 | 2 | app 3 / library 1 |
| `isOpenConfirmationPanel` | 1 | 1 | app 2 / library 0 |
| `isOpenSupportedCountryPanel` | 1 | 2 | app 3 / library 0 |
| `isProfileDataChanged` | 1 | 1 | app 2 / library 0 |
| `isRecordToUResponseInProgress` | 1 | 3 | app 4 / library 0 |
| `isResizing` | 2 | 3 | app 0 / library 5 |
| `isSaveInProgress` | 1 | 3 | app 4 / library 0 |
| `isTermsOfUseContentInProgress` | 1 | 3 | app 4 / library 0 |
| `isTransitionStarted` | 1 | 3 | app 0 / library 4 |
| `isUnmaskedPhoneInProgress` | 2 | 5 | app 7 / library 0 |
| `isValidateProfileInProgress` | 1 | 3 | app 4 / library 0 |
| `isvalidateSVCodeInProgress` | 1 | 3 | app 4 / library 0 |
| `Jr` | 1 | 1 | app 0 / library 2 |
| `Ke` | 1 | 1 | app 0 / library 2 |
| `keepTooltipVisible` | 1 | 2 | app 0 / library 3 |
| `Ki` | 1 | 1 | app 0 / library 2 |
| `loaded` | 5 | 3 | app 0 / library 8 |
| `loading` | 14 | 37 | app 0 / library 51 |
| `meta` | 2 | 1 | app 0 / library 3 |
| `mountOnEnter` | 1 | 1 | app 0 / library 2 |
| `mutationEventsAdded_` | 1 | 2 | app 0 / library 3 |
| `ndsReady` | 1 | 1 | app 0 / library 2 |
| `noIcon` | 1 | 1 | app 1 / library 1 |
| `notified` | 1 | 2 | app 0 / library 3 |
| `Oe` | 1 | 1 | app 0 / library 2 |
| `open` | 1 | 2 | app 1 / library 2 |
| `ordinal` | 1 | 1 | app 0 / library 2 |
| `parent` | 1 | 1 | app 0 / library 2 |
| `passive` | 4 | 4 | app 0 / library 8 |
| `paused` | 1 | 5 | app 0 / library 6 |
| `phoneVerified` | 1 | 1 | app 2 / library 0 |
| `profileSaving` | 1 | 2 | app 3 / library 0 |
| `Re` | 1 | 1 | app 0 / library 2 |
| `removed` | 2 | 1 | app 0 / library 3 |
| `REQUIRED` | 1 | 1 | app 0 / library 2 |
| `responsive` | 1 | 1 | app 0 / library 2 |
| `returnFocusOnDeactivate` | 1 | 1 | app 0 / library 2 |
| `saveSuccess` | 1 | 3 | app 4 / library 0 |
| `scrollDown` | 2 | 2 | app 0 / library 4 |
| `seenCR` | 1 | 3 | app 0 / library 4 |
| `show` | 2 | 5 | app 7 / library 0 |
| `showError` | 3 | 6 | app 9 / library 0 |
| `showFeedback` | 3 | 6 | app 9 / library 0 |
| `showPlatformText` | 1 | 1 | app 2 / library 0 |
| `showSecureValidation` | 1 | 2 | app 3 / library 0 |
| `showSuccess` | 2 | 3 | app 5 / library 0 |
| `showSV` | 1 | 1 | app 2 / library 0 |
| `Si` | 1 | 1 | app 0 / library 2 |
| `slim` | 16 | 1 | app 16 / library 1 |
| `sort` | 1 | 1 | app 0 / library 2 |
| `status` | 1 | 10 | app 11 / library 0 |
| `systemError` | 2 | 1 | app 3 / library 0 |
| `termOfUseAccepted` | 1 | 1 | app 2 / library 0 |
| `triggerHasFocus` | 1 | 1 | app 0 / library 2 |
| `unmountOnExit` | 1 | 1 | app 0 / library 2 |
| `updatingPassword` | 1 | 2 | app 3 / library 0 |
| `validateError` | 1 | 3 | app 4 / library 0 |
| `validatingToken` | 1 | 2 | app 2 / library 1 |
| `value` | 27 | 2 | app 1 / library 28 |
| `vcValidated` | 1 | 1 | app 2 / library 0 |
| `visible` | 1 | 2 | app 0 / library 3 |
| `writable` | 86 | 6 | app 0 / library 92 |

## Reducer and state-associated fields

| Key | Values | Count | Sources |
| --- | --- | ---: | --- |
| `alphaCheckMarkDisabled` | `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `createPasswordFailed` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `deactivateStatus` | `false` | 1 | `45236.bundle.4cc2ec85192dfe378162.js` |
| `disableConfirm` | `false`, `true` | 5 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `disableForm` | `false`, `true` | 8 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `disableStepOneConfirm` | `false`, `true` | 4 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `disableStepThreeConfirm` | `false`, `true` | 4 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `disableStepTwoConfirm` | `false`, `true` | 2 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isAccountSettingsSectionVisible` | `true` | 1 | `99973.bundle.1992235788cd8e6760cc.js` |
| `isAddMobileMsgBoxOpen` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isAlertPreferencesInProgress` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `isAlertPreferencesSectionVisible` | `true` | 1 | `99973.bundle.1992235788cd8e6760cc.js` |
| `isBypassSelected` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isContactDataInProgress` | `false`, `true` | 5 | `90627.bundle.774396b5bb79244ed884.js` |
| `isContactDetailsSectionVisible` | `true` | 1 | `99973.bundle.1992235788cd8e6760cc.js` |
| `isCountryCodesInProgress` | `false`, `true` | 7 | `90627.bundle.774396b5bb79244ed884.js` |
| `isCsrfTokenInProgress` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `isEditProfileInfoInProgress` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `isfetchVerifyPhoneInfoInProgress` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `isOpenConfirmationPanel` | `false`, `true` | 2 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isOpenSupportedCountryPanel` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isPerusal` | `false` | 5 | `15208.bundle.b2581fcf9159471308e7.js`<br>`45236.bundle.4cc2ec85192dfe378162.js`<br>`69453.chunk.36716f8b5afaaf4be835.js`<br>`90627.bundle.774396b5bb79244ed884.js` |
| `isProfileDataChanged` | `false`, `true` | 2 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `isRecordToUResponseInProgress` | `false`, `true` | 4 | `15208.bundle.b2581fcf9159471308e7.js` |
| `isSaveInProgress` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `isTermsOfUseContentInProgress` | `false`, `true` | 4 | `15208.bundle.b2581fcf9159471308e7.js` |
| `isUnmaskedPhoneInProgress` | `false`, `true` | 7 | `90627.bundle.774396b5bb79244ed884.js` |
| `isValidateProfileInProgress` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `isvalidateSVCodeInProgress` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `loading` | `false`, `true` | 51 | `15208.bundle.b2581fcf9159471308e7.js`<br>`45236.bundle.4cc2ec85192dfe378162.js`<br>`90627.bundle.774396b5bb79244ed884.js`<br>`99973.bundle.1992235788cd8e6760cc.js` |
| `numCheckMarkDisabled` | `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `perusal` | `false` | 3 | `15208.bundle.b2581fcf9159471308e7.js`<br>`69453.chunk.36716f8b5afaaf4be835.js`<br>`99973.bundle.1992235788cd8e6760cc.js` |
| `phoneVerified` | `false`, `true` | 2 | `90627.bundle.774396b5bb79244ed884.js` |
| `profileSaving` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `pwdLengthCheckMarkDisabled` | `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `recordToUResponseError` | `true` | 2 | `15208.bundle.b2581fcf9159471308e7.js` |
| `saveSuccess` | `false`, `true` | 4 | `90627.bundle.774396b5bb79244ed884.js` |
| `show` | `false`, `true` | 7 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showError` | `false`, `true` | 9 | `45236.bundle.4cc2ec85192dfe378162.js`<br>`90627.bundle.774396b5bb79244ed884.js`<br>`99973.bundle.1992235788cd8e6760cc.js` |
| `showErrorMsg` | `false` | 1 | `99973.bundle.1992235788cd8e6760cc.js` |
| `showFeedback` | `false`, `true` | 9 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSecureValidation` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSuccess` | `false`, `true` | 5 | `45236.bundle.4cc2ec85192dfe378162.js`<br>`58815.bundle.69941a6616c07e61aa7c.js`<br>`83561.bundle.24f5cda3cc34209fd608.js` |
| `showSuccessConfirmation` | `false` | 2 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSuccessData` | `false` | 1 | `45236.bundle.4cc2ec85192dfe378162.js` |
| `showSv` | `false` | 2 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `showSV` | `false`, `true` | 2 | `90627.bundle.774396b5bb79244ed884.js` |
| `specialCharCheckMarkDisabled` | `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `status` | `false`, `true` | 11 | `45236.bundle.4cc2ec85192dfe378162.js`<br>`90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `systemError` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `updatingPassword` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `validateError` | `false`, `true` | 4 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `validateProfileError` | `true` | 1 | `90627.bundle.774396b5bb79244ed884.js` |
| `validateSVCodeError` | `true` | 1 | `90627.bundle.774396b5bb79244ed884.js` |
| `validatingToken` | `false`, `true` | 3 | `90460.chunk.6fd8af48bf6f8fcdcfb0.js` |
| `vcValidated` | `false`, `true` | 2 | `90627.bundle.774396b5bb79244ed884.js` |

## Perusal control path

The Terms-of-Use MFE initializes `isPerusal` to false, accepts the host profile `perusal` value with a false fallback, and binds the resulting state to UI `disabled` properties. These are dynamic mode controls, not a static global feature-off flag.

| Control key | Referenced state | Control | Test/value | Source offset |
| --- | --- | --- | --- | ---: |
| `disabled` | `isPerusal` | `i.Button` | test `terms-of-use-continue-button` | 9223 |
| `disabled` | `isPerusal + D` | `i.RadioButton` | test `terms-of-use-accept-radio-button` | 8443 |
| `disabled` | `isPerusal + D` | `i.RadioButton` | test `terms-of-use-decline-radio-button` | 8961 |

## Nested contact/account control bindings

| Feature source | Control key | Referenced state/expression | Control/test ID | Offset |
| --- | --- | --- | --- | ---: |
| user-contact-details-remove | `checked` | `receptionist + phone` | `m.RadioButton` | 18163 |
| user-contact-details-remove | `checked` | `receptionist + phone` | `m.RadioButton` | 18438 |
| user-account-settings-auto-access | `disabled` | `isPerusal` | `n.Button` | 3316 |
| user-account-settings-gates | `disabled` | `isPerusal` | `o.Button` | 3316 |
| user-account-settings-gates | `disabled` | `isPerusal` | `a.Button` | 6564 |
| user-contact-details-save | `disabled` | `isPerusal` | `s.Button` | 3466 |
| user-contact-details-remove | `disabled` | `isPerusal` | `m.Button` | 13632 |
| user-account-settings-gates | `isAccountSettingsSectionVisible` | `ssoOnlyUser` | `unknown` | 8352 |
| user-contact-details-remove | `isPerusal` | `isPerusal` | `x` | 22963 |
| user-contact-details-remove | `isPerusal` | `isPerusal` | `C` | 23805 |
| user-contact-details-save | `isValidateProfileInProgress` | `isValidateProfileInProgress` | `b` | 9022 |
| user-contact-details-save | `open` | `ee` | `m.A` | 9432 |
| user-account-settings-gates | `open` | `O` | `p` | 12034 |
| user-account-settings-auto-access | `open` | `open` | `r.MessageBar` | 323 |
| user-account-settings-gates | `open` | `open` | `r.MessageBar` | 323 |
| user-account-settings-gates | `open` | `open` | `a.MessageBox` | 5976 |
| user-contact-details-save | `open` | `open` | `s.MessageBox` | 900 |
| user-contact-details-save | `open` | `open` | `update-alert-preferences-modal` | 1826 |
| user-contact-details-remove | `open` | `open` | `r.MessageBox` | 9208 |
| user-contact-details-remove | `open` | `open` | `m.MessageBox` | 11493 |
| user-contact-details-remove | `open` | `open + U` | `g` | 23950 |
| user-contact-details-save | `open` | `openEditPanel` | `s.Panel` | 8490 |
| user-contact-details-save | `open` | `Q` | `p` | 9329 |
| user-contact-details-save | `open` | `re` | `h` | 9658 |
| user-account-settings-gates | `open` | `showSuccess` | `b.n` | 12096 |
| user-account-settings-auto-access | `open` | `userAccountSettings + showSuccess` | `u.n` | 1792 |
| user-account-settings-gates | `open` | `userAccountSettings + showSuccess` | `u.n` | 1792 |
| user-account-settings-gates | `showErrorMsg` | `showError` | `unknown` | 12533 |

### Consumer guards

| Feature source | Guard type | Referenced keys | Condition | Offset |
| --- | --- | --- | --- | ---: |
| user-account-settings-auto-access | early-return | `useEffect`, `c`, `useDispatch`, `lX`, `o`, `m`, `E`, `e`, `userAccountSettings`, `prefInfo`, `autoAccess`, `b`, `userSelected`, `tB`, `d`, `authorized` | `(0,c.useEffect)(function(){_((0,o.lX)()),_((0,E.m)())},[_]),(0,c.useEffect)(function(){var e;(null==p\|\|null==(e=p.prefInfo)?void 0:e.autoAccess)&&b(p.prefInfo.autoAccess.userSelected===d.tB)},[p]),!(null==P?void 0:P.authorized)` | 1356 |
| user-account-settings-gates | early-return | `useEffect`, `i`, `useDispatch`, `lX`, `c`, `m`, `f`, `e`, `userAccountSettings`, `prefInfo`, `autoAccess`, `userSelected`, `tB`, `d`, `authorized` | `(0,i.useEffect)(function(){A((0,c.lX)()),A((0,f.m)())},[A]),(0,i.useEffect)(function(){var e;(null==j\|\|null==(e=j.prefInfo)?void 0:e.autoAccess)&&m(j.prefInfo.autoAccess.userSelected===d.tB)},[j]),!(null==C?void 0:C.authorized)` | 1356 |
| user-account-settings-gates | conditional-branch | `sso`, `I`, `userAccountSettings`, `status` | `"boolean"==typeof T&&T&&I(T),N&&N.status` | 8062 |
| user-account-settings-gates | conditional-branch | `y` | `y` | 8167 |
| user-contact-details-save | conditional-branch | `te`, `length`, `X`, `Pi`, `c` | `te(!1),X.length<c.Pi` | 9459 |
| user-contact-details-state | conditional-branch | `r` | `r` | 11490 |
| user-contact-details-state | conditional-branch | `isfetchVerifyPhoneInfoInProgress`, `e`, `fetchVerifyPhoneInfoData`, `payload`, `fetchVerifyPhoneInfoError`, `transactionId` | `e.isfetchVerifyPhoneInfoInProgress=!1,e.fetchVerifyPhoneInfoData=t,e.fetchVerifyPhoneInfoError=null,t&&t.transactionId` | 34159 |

## Environment maps

These URLs were parsed as inert literals from production source. `contacted` is false for every mapped target.

| Mapping key | Variants | Environment labels | Production hostname(s) |
| --- | ---: | --- | --- |
| `accountUnlockMFE` | 1 | `dev`, `fix`, `hos`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `CEOPT_MFE_ALERTPREFERENCES` | 1 | `dev`, `fix`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `CEOPT_MFE_FOOTERMFE` | 2 | `dev`, `fix`, `hos`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `CEOPT_MFE_USER_ACCOUNT_SETTINGS` | 1 | `dev`, `fix`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `CEOPT_MFE_USER_CONTACT_DETAILS` | 1 | `dev`, `fix`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `CIAM_APP_OTP_MFE` | 1 | `dev`, `fix`, `local`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `consentMFE` | 1 | `dev`, `fix`, `hos`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `loginMFE` | 1 | `dev`, `fix`, `hos`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `MFE_18199B69_86C2_4DD9_9D77_B264C110A5B2` | 1 | `fix`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `MFE_5F757533_72B3_4D1A_BDE2_3D59E432BE10` | 1 | `fix`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `MFE_6DFC4560_E6F2_478F_8D95_E33063EDA3B5` | 1 | `dev`, `fix`, `hos`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `MFE_A4ED76E5_C005_4F9F_A664_CFFD3134C6A6` | 1 | `dev`, `fix`, `local`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `MFE_C87ED3F2_2D6A_46C3_A875_C9BBFCC17C9F` | 1 | `dev`, `fix`, `local`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `pwcMFE` | 1 | `dev`, `fix`, `hos`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `SELF_HELP_MFE` | 1 | `dev`, `fix`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |
| `svMFE` | 1 | `dev`, `fix`, `hos`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `tokenMFE` | 1 | `dev`, `fix`, `hos`, `prd`, `sit`, `uat` | `ciam.ceo.wellsfargo.com` |
| `WFRIA_MFE_LOGINMFE` | 2 | `dev`, `fix`, `hos`, `local`, `prd`, `sit`, `uat` | `wellsceomfes.ceo.wellsfargo.com` |

## Files

- `blanche-boolean-inventory.json` — complete machine-readable inventory with counts, values, source/chunk/module offsets, roles, and snippets.
- `run-blanche-boolean-inventory.mjs` — reproducible bounded collector/parser.

## Caveat

A false default, reducer state, UI option, or library descriptor is not proof that a product feature is globally disabled. Runtime responses, server layouts, entitlements, and later state transitions can change values.

