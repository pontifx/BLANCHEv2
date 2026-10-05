# Site Tear Sheet

The BLANCHE Report surface creates a per-site explanation of what BLANCHE observed. It combines the
current site's complete browser capture with related tester activity, then exposes the same report
through two audience-specific modes.

## Operator workflow

1. Open the target page in the active tab.
2. Open `Report` in the BLANCHE side panel or DevTools panel.
3. Choose `Capture Full Site (reloads)` for document-start instrumentation, or `Passive Snapshot`
   when reloading would disturb the current page state.
4. Check the collection mode, timestamps, warnings, errors, and visibility gaps before interpreting
   the results.
5. Use `Stakeholder` to review the explainable tear sheet and `Download HTML` to save that view.
6. Use `JSON Evidence` for the complete evidence model. Choose `Download JSON` for a file or `Copy
   JSON` for the clipboard.

The report is site-scoped. BLANCHE correlates records only when their normalized hostname exactly
matches the captured site's hostname; unrelated engagement activity is not presented as evidence
for that site. Correlated records retain their own timestamps and are not represented as proof that
they came from the same capture session.

## Stakeholder mode

Stakeholder mode emphasizes what was seen, why it matters for follow-on testing, and where coverage
was incomplete. It includes:

- target identity, capture time, collection mode, and report/source identifiers;
- an executive summary and artifact counts by category;
- page and frame context plus browser-visible resources;
- browser-only observations such as storage keys, IndexedDB, Cache Storage, workers, service
  workers, blob/data URLs, and runtime instrumentation;
- site-correlated findings and their evidence;
- related search tasks/results, including `manual-required` states;
- acquired-document metadata, hashes, interesting-term counts, extracted URLs, and disposition;
- latent-feature candidates, confidence, control surface, and supporting evidence;
- site-correlated activity; and
- collector status, provenance, warnings, errors, and visibility gaps.

Raw captured values are masked in Stakeholder mode. This makes the report easier to explain and
reduces accidental disclosure, but it does not make the HTML automatically safe for unrestricted
distribution. URLs, filenames, finding descriptions, and contextual evidence can still disclose
sensitive details. Review the exported HTML for its intended audience.

## JSON Evidence mode

JSON Evidence is the technical, loss-preserving form of the report. It contains:

- the full source BLANCHE browser export;
- the site-correlated findings, searches, documents, latent-feature evidence, and activity used by
  the Stakeholder view;
- report-generation metadata and correlation context; and
- original provenance, warnings, errors, and visibility gaps.

Unlike the Stakeholder view, JSON Evidence is not a masked presentation. The source capture may
contain browser-storage values and other sensitive page context. Treat downloaded or copied JSON as
assessment evidence: restrict access, use an approved storage location, and inspect it before
sharing.

## Provenance and collection limits

BLANCHE labels artifact provenance as `observed`, `inferred`, or `unavailable`, with a confidence
level and source references. The report preserves those labels. An observed resource means that the
browser reported its presence; it does not necessarily establish the resource's complete creation
or network lineage.

Warnings, errors, and visibility gaps are part of the evidence rather than cosmetic diagnostics.
Cross-origin frames, restricted URLs, unavailable APIs, collection timing, permissions, and passive
capture can all produce partial coverage. A low count with a visibility gap must not be described as
proof that no other artifacts exist.

## Relationship to HAR

The site tear sheet is HAR-like in that it inventories page resources and includes available
navigation/resource timing and size information. It goes beyond a conventional HAR in several
browser-only areas, including DOM resources, Web Storage, IndexedDB catalogs, Cache Storage,
workers, service workers, blobs, data URLs, runtime feature evidence, findings, documents, and
site-correlated activity.

It is not a full HAR capture. BLANCHE does not preserve complete raw HTTP transactions, request or
response header values, response bodies, cookies, HTTP status for every resource, or a complete
network waterfall. Use Burp or another HTTP capture source when conclusions require those details,
and use the BLANCHE tear sheet to explain the browser-side evidence that network capture alone may
miss.
