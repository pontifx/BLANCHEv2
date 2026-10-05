# Search Operator Compatibility Matrix

Last reviewed: **2026-09-09**

This document is the human-readable companion to
`chromium-extension/src/shared/searchOperatorCatalog.ts`. The TypeScript catalog is the
source of truth used by BLANCHE. Operator IDs are normalized across Google, Bing, and
DuckDuckGo even when the engines use different syntax or semantics.

## Status and generation policy

| Mark | Catalog status | Meaning |
| --- | --- | --- |
| **D** | `documented` | Present in current first-party vendor documentation. |
| **O** | `observed` | Reproduced in a current controlled check, but absent from the vendor's current operator contract. |
| **F** | `fragile` | Experimental, soft/relaxed, vertical-only, or otherwise unreliable as a hard constraint. |
| **R** | `deprecated` | Explicitly retired, disabled, or tied to a discontinued product. Never emitted. |
| **X** | `unsupported` | No current supported query syntax was found. Never emitted. |

`safeForGeneration` means only that BLANCHE may use the syntax for the named engine and
surface. It is not a claim that the engine will return exhaustive results, and it does
not grant authorization to investigate a target. Users remain responsible for scope,
law, terms of service, privacy, and rate limits.

## Methodology

The review prioritizes current first-party help and product documentation. Google's
current public help intentionally lists only a short core, so the broader Google field
operators are marked **O** or **F** and cite both the 2024 Daniel Russell field guide
and a July 2026 controlled operator test where available. A plausible-looking result
page is not enough to establish support: engines often ignore an unknown prefix and
run the remaining words as an ordinary query.

An operator is marked **R** when a vendor or credible vendor-linked record explicitly
documents retirement. Absence from current documentation is otherwise treated as **X**
unless there is strong current observational evidence. UI settings and URL parameters
are not promoted into query operators.

## Boolean, exact-match, and routing operators

| Normalized ID | Google | Bing | DuckDuckGo | Generation guidance |
| --- | --- | --- | --- | --- |
| `exact-phrase` | **D** `"{phrase}"`; exact organic phrase, with special-module caveats ([Google Help][g-help]) | **D** `"{phrase}"`; exact phrase ([Bing options][b-options]) | **F** `"{phrase}"`; may fall back to related results ([DDG syntax][d-syntax]) | G/B/DDG: emit; do not promise database-style exactness on DDG. |
| `and` | **F** adjacent terms; ordinary multi-term relevance, not a hard Boolean token ([Google Advanced][g-advanced], [field guide][g-field]) | **D** adjacent terms, `AND`, or `&`; default AND, first ten terms only ([Bing options][b-options]) | **X** adjacent terms are described as results about either term ([DDG syntax][d-syntax]) | G/B: emit supported form. DDG: split constrained searches or quote. |
| `or` | **D** `{a} OR {b}`; uppercase `OR` ([Google Advanced][g-advanced]) | **D** `{a} OR {b}` or `{a} &#124; {b}`; uppercase `OR` ([Bing options][b-options]) | **X** no explicit Boolean contract ([DDG syntax][d-syntax]) | G/B: emit. DDG: expand into separate queries. |
| `not` | **D** `-{term}` or `-"{phrase}"`; no space after minus ([Google Help][g-help]) | **D** `NOT {term}` or `-{term}`; uppercase `NOT` ([Bing options][b-options]) | **F** `-{term}` means fewer results, not guaranteed exclusion ([DDG syntax][d-syntax]) | All: emit, but label DDG's behavior as soft. |
| `plus` | **R** `+{term}` exact-term behavior removed; use quotes ([Google blog][g-plus]) | **D** `+{term}` requires/includes a term or stop word ([Bing options][b-options]) | **F** `+{term}` is a soft boost ([DDG syntax][d-syntax]) | Bing/DDG only; never translate Bing's hard requirement into DDG. |
| `grouping` | **X** parentheses are not a supported Boolean grouping contract ([field guide][g-field]) | **D** `({clause})`; highest precedence ([Bing options][b-options]) | **X** not documented ([DDG syntax][d-syntax]) | Bing only. Expand branches into separate queries elsewhere. |
| `wildcard` | **F** `"{term} * {term}"`; historical whole-word gap, not substring globbing ([field guide][g-field], [2026 test][g-observed]) | **X** unlisted punctuation is ignored ([Bing options][b-options]) | **X** not documented ([DDG syntax][d-syntax]) | Do not auto-emit; prefer explicit alternatives. |
| `ddg-semantic` | **X** no equivalent token ([Google Help][g-help]) | **X** no equivalent token ([Bing options][b-options]) | **F** `~"{phrase}"`; vendor-labeled experimental semantic expansion ([DDG syntax][d-syntax]) | DDG only, opt-in, and visibly experimental. |
| `ddg-first-result` | **X** | **X** | **D** `\{query}` routes directly to the first result ([DDG syntax][d-syntax]) | Never auto-emit: it bypasses result review. |
| `ddg-bang` | **X** | **X** | **D** `!{bang} {query}` routes to an external site's search ([DDG syntax][d-syntax], [bang directory][d-bangs]) | Never auto-emit. Prefer an explicitly reviewed NERD-mode target template. |
| `safe-search` | **X** SafeSearch is a setting | **X** SafeSearch is a control | **D** `{query} !safeon` or `!safeoff`; changes filtering ([DDG syntax][d-syntax]) | Never auto-emit; preserve the user's setting unless explicitly changed. |

## Scope and indexed-content operators

| Normalized ID | Google | Bing | DuckDuckGo | Generation guidance |
| --- | --- | --- | --- | --- |
| `site` | **D** `site:{domain}` or `site:{urlPrefix}`; includes subdomains and is not exhaustive ([Google site docs][g-site]) | **D** `site:{domain}`, `site:{tld}`, or shallow `site:{directory}` ([Bing keywords][b-keywords]) | **F** `site:{domain}`; documented with global reliability warning ([DDG syntax][d-syntax]) | All: emit. Never treat counts as an inventory. |
| `negative-site` | **D** `-site:{domain}` from documented primitives ([Google Help][g-help], [site docs][g-site]) | **D** `-site:{domain}` or `NOT site:{domain}` ([Bing options][b-options], [keywords][b-keywords]) | **F** `-site:{domain}` is the documented hard domain exclusion ([DDG syntax][d-syntax]) | All: emit. |
| `url` | **X** no current index-presence prefix ([Google site docs][g-site]) | **D** `url:{domainOrUrl}` checks index presence, not a substring ([Bing keywords][b-keywords]) | **X** no equivalent ([DDG syntax][d-syntax]) | Bing only; `site:` is only a best-effort alternative elsewhere. |
| `intitle` | **O** `intitle:{term}` or `intitle:"{phrase}"` ([field guide][g-field], [2026 test][g-observed]) | **D** `intitle:{term}`; one term per occurrence ([Bing keywords][b-keywords]) | **F** `intitle:{term}` ([DDG syntax][d-syntax]) | All: emit; chain one Bing clause per term. |
| `allintitle` | **F** `allintitle:{terms}` relaxed in current testing ([field guide][g-field], [2026 test][g-observed]) | **X** no token ([Bing keywords][b-keywords]) | **X** no token ([DDG syntax][d-syntax]) | Do not emit; repeat `intitle:`. |
| `inurl` | **F** `inurl:{term}` or `inurl:"{phrase}"`; real but relaxed effect ([field guide][g-field], [2026 test][g-observed]) | **R** `inurl:{term}` was disabled and is absent from current docs ([Bing retirement][b-inurl], [keywords][b-keywords]) | **F** `inurl:{term}` ([DDG syntax][d-syntax]) | G/DDG: emit with validation. Bing: use supported `site:` scope where applicable. |
| `allinurl` | **F** `allinurl:{terms}` is relaxed ([field guide][g-field], [2026 test][g-observed]) | **X** | **X** | Do not emit; repeat `inurl:` where supported and inspect returned URLs. |
| `intext` | **O** `intext:{term}` or `intext:"{phrase}"` ([field guide][g-field], [2026 test][g-observed]) | **X** use `inbody:` ([Bing keywords][b-keywords]) | **X** ([DDG syntax][d-syntax]) | Google only. |
| `allintext` | **O** `allintext:{terms}` ([field guide][g-field], [2026 test][g-observed]) | **D** capability via repeated `inbody:{term}` ([Bing keywords][b-keywords]) | **X** | G/B: emit native/repeated form. |
| `inbody` | **X** use `intext:` | **D** `inbody:{term}`; one term per occurrence ([Bing keywords][b-keywords]) | **X** | Bing only. |
| `inanchor` | **O** `inanchor:{term}` or quoted phrase; sampled, not a backlink inventory ([field guide][g-field], [2026 test][g-observed]) | **D** `inanchor:{term}`; one term per occurrence ([Bing keywords][b-keywords]) | **X** | G/B: emit. Never report the results as a complete backlink list. |
| `allinanchor` | **F** `allinanchor:{terms}` lacks a current contract ([field guide][g-field]) | **D** capability via repeated `inanchor:{term}` ([Bing keywords][b-keywords]) | **X** | Bing repeated form only; use repeated `inanchor:` rather than Google's all-in alias. |

## File, date, proximity, locale, and feed operators

| Normalized ID | Google | Bing | DuckDuckGo | Generation guidance |
| --- | --- | --- | --- | --- |
| `filetype` | **D** `filetype:{extension}`; indexed types only ([Google operator docs][g-operators], [file types][g-files]) | **D** `filetype:{type}`; document type ([Bing keywords][b-keywords]) | **F** `filetype:{type}` for pdf, doc/docx, xls/xlsx, ppt/pptx, html ([DDG syntax][d-syntax]) | All: emit using each engine's supported set. |
| `ext` | **F** `ext:{extension}` is a less reliable historical alias ([2026 test][g-observed]) | **D** `ext:{extension}` matches filename extension ([Bing keywords][b-keywords]) | **X** ([DDG syntax][d-syntax]) | Bing only; use `filetype:` on Google/DDG. |
| `contains` | **X** | **D** `contains:{extension}` finds pages linking to that extension, not files themselves ([Bing keywords][b-keywords]) | **X** | Bing only; keep its semantics distinct from `filetype:`. |
| `before` | **D** `before:YYYY-MM-DD` or `before:YYYY`; date may be inferred ([Google Help][g-help]) | **X** query token; use result-page date filter ([Bing options][b-options]) | **X** query token; use date UI/custom range ([DDG dates][d-dates]) | Google only. UI filters may be represented separately, never injected as text. |
| `after` | **D** `after:YYYY-MM-DD` or `after:YYYY`; date may be inferred ([Google Help][g-help]) | **X** query token; use result-page date filter ([Bing options][b-options]) | **X** query token; use date UI/custom range ([DDG dates][d-dates]) | Google only. Combine with `before:` for a bounded range. |
| `numeric-range` | **D** `{minimum}..{maximum}`; numeric matching, not a publication-date filter ([Google Advanced][g-advanced]) | **X** | **X** | Google only. |
| `proximity` | **O** `{a} AROUND({distance}) {b}`; uppercase, unordered ([field guide][g-field], [2026 test][g-observed]) | **F** `{a} NEAR:{distance} {b}` is circulated but absent from the current contract ([Bing options][b-options], [keywords][b-keywords]) | **X** | Google only for automatic generation; quote or split searches elsewhere. |
| `language` | **X** query token; use Advanced Search/result-language UI ([Google Advanced][g-advanced]) | **D** `language:{code}` ([Bing keywords][b-keywords]) | **X** query token; language/region are settings ([DDG syntax][d-syntax]) | Bing only. |
| `location` | **X** query token; use region UI or explicit place terms ([Google Advanced][g-advanced]) | **D** `loc:{countryCode}` or `location:{countryCode}` ([Bing keywords][b-keywords]) | **X** query token ([DDG syntax][d-syntax]) | Bing only; label region-dependent behavior. |
| `ip` | **X** | **D** `ip:{dottedQuad}` finds sites hosted on an IPv4 address ([Bing keywords][b-keywords]) | **X** | Bing only; shared hosting can create unrelated matches. |
| `prefer` | **X** | **D** `prefer:{termOrOperator}` is a ranking boost, not a filter ([Bing keywords][b-keywords]) | **X**; closest behavior is soft `+{term}` ([DDG syntax][d-syntax]) | Bing only; do not describe it as required. |
| `feed` | **X** | **D** `feed:{term}` finds RSS or Atom feeds ([Bing keywords][b-keywords]) | **X** | Bing only. |
| `hasfeed` | **X** | **D** `hasfeed:{term}` finds pages exposing a related feed ([Bing keywords][b-keywords]) | **X** | Bing only. |
| `source` | **F** `source:{publisher}` is legacy Google News syntax; use the current publisher UI ([Google News help][g-news], [field guide][g-field]) | **X** | **X** | Do not auto-emit; use `site:` or a news-surface filter. |

## Image-only operators

| Normalized ID | Google | Bing | DuckDuckGo | Generation guidance |
| --- | --- | --- | --- | --- |
| `imagesize` | **D** `imagesize:{width}x{height}` on Google Images only ([Google image docs][g-images]) | **X** query token; use image UI | **X** query token; use image UI | Google Images only; never inject into a general web query. |
| `src` | **D** `src:{imageUrl}` on Google Images; exact image `src` reference ([Google image docs][g-images]) | **X** | **X** | Google Images only; retrieval is not exhaustive. |

## Retired, legacy, and non-filter prefixes

These rows remain in the catalog to prevent stale dork lists from being emitted. Their
presence is negative knowledge, not a recommendation.

| Normalized ID | Google | Bing | DuckDuckGo | Replacement |
| --- | --- | --- | --- | --- |
| `cache` | **R** `cache:{url}` no longer works ([Google changelog][g-changelog]) | **X** ([Bing options][b-options]) | **X** ([DDG syntax][d-syntax]) | Use a lawful web archive or authorized current capture. |
| `related` | **R** `related:{url}` no longer supported ([Google changelog][g-changelog]) | **F** externally circulated, absent from current docs ([Bing options][b-options], [keywords][b-keywords]) | **X** | Compare domains ranking for the same neutral topic. |
| `info` | **R** `info:{url}`/`id:{url}` retired ([Google retirement post][g-info]) | **F** externally circulated, absent from current docs | **X** | Search Console URL Inspection for owned properties; Bing `url:` only checks index presence. |
| `link` | **R** `link:{url}` retired ([retirement report][g-link]) | **R** `link:`/`linkfromdomain:` are legacy; Link Explorer retired ([Bing retirement][b-link]) | **X** | Use an authorized backlink index. |
| `synonym` | **R** `~{term}` removed after automatic synonym expansion ([field guide][g-field]) | **X** | **X**; do not confuse with DDG `~"phrase"` | Use explicit `OR` alternatives where supported. |
| `daterange` | **R** `daterange:{julianStart}-{julianEnd}` is ignored in current testing ([2026 test][g-observed]) | **X** | **X** | Google `after:` + `before:`; Bing/DDG date UI. |
| `phonebook` | **R** `phonebook:`, `rphonebook:`, `bphonebook:` ([field guide][g-field], [2026 test][g-observed]) | **X** | **X** | Consent-respecting official public directories. |
| `legacy-groups` | **R** `author:`, `group:`, `insubject:` were Google Groups fields ([field guide][g-field]) | **X** | **X** | Current Groups UI or a site-scoped web query. |
| `legacy-blog-search` | **R** `blogurl:`, `inpostauthor:`, `allinpostauthor:`, `inposttitle:` belonged to discontinued Blog Search ([field guide][g-field]) | **X** | **X** | Compose `site:`, `intitle:`, `inurl:`, and exact phrases. |
| `patent` | **R** `patent:{number}` did not show operator behavior in current testing ([2026 test][g-observed]) | **X** | **X** | Use an official patent database such as Google Patents. |
| `utility-answer` | **F** `define`, `weather:`, `stocks:`, `movie:` may trigger answer cards, not index filters ([field guide][g-field], [2026 test][g-observed]) | **X** as advanced index operators | **X** as query operators; Instant Answers are result features ([DDG sources][d-sources]) | Use natural-language utility queries or the dedicated product; never mix these into a dork as constraints. |

## Engine-wide caveats

### Google

- Search operators are bounded by Google's index and retrieval systems. `site:` results
  and counts are explicitly not exhaustive.
- `before:` and `after:` operate on Google's inferred document dates, which may differ
  from original publication time.
- Quotes and exclusions primarily constrain organic web results. Local, shopping,
  knowledge, and other special modules may behave differently.
- **O** and **F** operators should be regression-tested periodically. They are not a
  first-party compatibility promise.

### Bing

- Bing uses only the first ten query terms.
- Current documented precedence is parentheses, quotes, `NOT`/`-`/`+`, `AND`/`&`, then
  `OR`/`|`. `NOT` and `OR` must be uppercase.
- `inanchor:`, `inbody:`, and `intitle:` take one term per occurrence.
- Availability and behavior can vary by market or region.

### DuckDuckGo

- DuckDuckGo explicitly warns that advanced syntax is not correct for every query
  because results come from varied sources.
- Traditional links are largely sourced from Bing, but Bing's query-language contract
  does **not** transitively apply to DuckDuckGo.
- Quoted, minus, plus, site, title, URL, and file-type behavior can be softened or
  broadened. Reports must describe the requested constraint, not claim every returned
  result satisfies it without validation.
- `\query`, bangs, and Safe Search tokens alter routing or settings; they are not
  ordinary result-matching operators.

## Source index

Primary and first-party sources:

- [Google Search refinement help][g-help]
- [Google Advanced Search form][g-advanced]
- [Google Search operator overview][g-operators]
- [Google `site:` documentation][g-site]
- [Google image-search operators][g-images]
- [Google indexable file types][g-files]
- [Google Search documentation changelog][g-changelog]
- [Google `info:` retirement post][g-info]
- [Google `+` operator retirement post][g-plus]
- [Google News publisher-filter help][g-news]
- [Bing advanced search options][b-options]
- [Bing advanced search keywords][b-keywords]
- [Bing's `inurl:` disablement record][b-inurl]
- [Bing Link Explorer retirement][b-link]
- [DuckDuckGo search syntax][d-syntax]
- [DuckDuckGo date filters][d-dates]
- [DuckDuckGo result sources][d-sources]
- [DuckDuckGo bangs][d-bangs]

Secondary observational and historical sources:

- [Daniel Russell's 2024 Google operator field guide][g-field]
- [July 2026 controlled Google operator test][g-observed]
- [Report of Google's confirmed `link:` retirement][g-link]

[g-help]: https://support.google.com/websearch/answer/2466433?hl=en
[g-advanced]: https://www.google.com/advanced_search
[g-operators]: https://developers.google.com/search/docs/monitor-debug/search-operators
[g-site]: https://developers.google.com/search/docs/monitor-debug/search-operators/all-search-site
[g-images]: https://developers.google.com/search/docs/monitor-debug/search-operators/image-search
[g-files]: https://developers.google.com/search/docs/crawling-indexing/indexable-file-types
[g-changelog]: https://developers.google.com/search/updates
[g-info]: https://developers.google.com/search/blog/2019/03/how-to-discover-suggest-google-selected
[g-plus]: https://search.googleblog.com/2011/11/search-using-your-terms-verbatim.html?hl=en
[g-field]: https://gwern.net/doc/technology/google/2024-02-08-danielmrussell-googleadvancedsearchoperators-alltheoperators.pdf
[g-observed]: https://seomator.com/blog/google-search-operators-cheat-sheet
[g-link]: https://searchengineland.com/google-officially-killed-off-link-command-267454
[g-news]: https://support.google.com/googlenews/answer/9005601?hl=en
[b-options]: https://support.microsoft.com/en-us/bing/advanced-search-options
[b-keywords]: https://support.microsoft.com/en-us/bing/advanced-search-keywords
[b-inurl]: https://blogs.bing.com/search/March-2007/We-are-flattered%2C-but
[b-link]: https://blogs.bing.com/webmaster/September-2015/Link-Explorer-Being-Retired-in-Webmaster-Tools
[d-syntax]: https://duckduckgo.com/duckduckgo-help-pages/results/syntax
[d-dates]: https://duckduckgo.com/duckduckgo-help-pages/features/dates
[d-sources]: https://duckduckgo.com/duckduckgo-help-pages/results/sources
[d-bangs]: https://duckduckgo.com/bangs
