# Wells Fargo Vantage unauthenticated JavaScript review

Run date: 2026-09-24

## Scope and method

- Ran BLANCHE's passive OSINT collector against `www.wellsfargo.com`.
- Followed the official public Vantage sign-on link without submitting a form or credentials.
- Fetched only scripts referenced by the public production sign-on page, with no credentials.
- Analyzed the bounded source bodies with BLANCHE's Delivered JavaScript analyzer.
- Did not request any extracted DEV or SIT URL.
- Did not retain response cookies or transient OAuth state, nonce, or PKCE values in this summary.

## Vantage authentication surface

- Official product page: `https://www.wellsfargo.com/com/vantage/`
- Sign-on entry: `https://wellsoffice.ceo.wellsfargo.com/`
- Canonical sign-on shell: `https://wellsoffice.ceo.wellsfargo.com/portal/signon/index.jsp`
- Authorization endpoint: `https://wellsceopf.ceo.wellsfargo.com/as/authorization.oauth2`

## Public bundle containing environment mappings

- URL: `https://wellsoffice.ceo.wellsfargo.com/ceosignon/MVP2.bundle.4ad597c3f52a94af6168.js`
- Anonymous response: HTTP 200, `text/javascript`, 45,068 bytes
- Last-Modified: `Mon, 21 Sep 2026 23:40:20 GMT`
- SHA-256: `939cb3af27ff554390c81a850c6ead1d0fc84fcb46b2b079180e9783a4b171cb`
- BLANCHE transform result: primary `bundled`; detected `bundled` and `minified`; not classified as `packed`

## Explicit DEV and SIT mappings

| Mapping | Environment | Hostname | Publicly embedded resource path |
| --- | --- | --- | --- |
| Login MFE (`WFRIA_MFE_LOGINMFE`) | SIT | `wcaloginmfesit.cfapps.wellsfargo.net` | `/login-mfe/auth/v1/remoteEntry.js` |
| Login MFE (`WFRIA_MFE_LOGINMFE`) | DEV | `wcaloginmfedev.cfapps.wellsfargo.net` | `/login-mfe/auth/v1/remoteEntry.js` |
| Self-help MFE (`MFE_6DFC4560_E6F2_478F_8D95_E33063EDA3B5`) | SIT | `wellsceomfes-sitd.ceo.wellsfargo.com` | `/selfhelpmfe/selfhelpmfe/remoteEntry.js` |
| Self-help MFE (`MFE_6DFC4560_E6F2_478F_8D95_E33063EDA3B5`) | DEV | `wellsceomfes-devd.ceo.wellsfargo.com` | `/selfhelpmfe/selfhelpmfe/remoteEntry.js` |
| Footer MFE (`CEOPT_MFE_FOOTERMFE`) | SIT | `wellsceomfes-sitd.ceo.wellsfargo.com` | `/footermfe/footermfe/v1/remoteEntry.js` |
| Footer MFE (`CEOPT_MFE_FOOTERMFE`) | DEV | `wellsceomfes-devd.ceo.wellsfargo.com` | `/footermfe/footermfe/v1/remoteEntry.js` |

Unique exposed DEV/SIT hostnames: 4.

The environment labels above are literal `sit:` and `dev:` keys in the anonymously served production bundle; they are not inferred from hostname spelling. Public disclosure alone does not establish reachability, exposure beyond the bundle, or security impact.
