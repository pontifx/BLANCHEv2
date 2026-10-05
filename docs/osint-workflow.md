# OSINT Workflow

## Scope

This workflow is intentionally limited to public, informational OSINT:
- public DNS
- public web resources
- public TLS metadata
- passive external OSINT tooling already approved and present on the operator host

Explicitly out of scope:
- exploitation
- active vulnerability validation
- severity assignment
- non-public data collection
- replacing established ProdPT testing methodology

## Chromium Role

The Chromium extension now includes the `OSINT Seed` module.

The primary Search section also runs persisted browser-based OSINT tasks. The built-in advanced
recipe covers public footprint, indexed files, archival references, JavaScript/source maps,
library/version terms, extracted URL/endpoint terms, infrastructure/certificates, and shipped
client feature terms. It reads the rendered result pages that it opened and records deduplicated
links as findings.

Search completion is deliberately literal:

- a rendered result set is complete;
- a rendered zero-result page is complete;
- a CAPTCHA, human-verification, access-denied, or unreadable challenge page is
  `manual-required`, not complete. BLANCHE preserves the exact query with Copy/Open controls.

Same-engine launch spacing and repeated-query cooldown both default to 300 ms. Search concurrency
defaults to one and is adjustable in Search throttle settings.

Use it from the side panel or DevTools panel:
1. Open the target application page.
2. Run `Seed OSINT From Tab`.
3. The module derives a normalized seed from the current tab URL plus browser-visible references such as anchors, scripts, stylesheets, images, forms, iframes, and manifests.
4. The seed is posted to Burp on `http://blanche.invalid/osint/seed`, with loopback fallback to `http://127.0.0.1:47625/api/blanche/osint/seed`.

## Burp Role

The Burp extension receives:
- browser exports on `/ingest`
- OSINT seeds on `/osint/seed`
- OSINT reports on `/osint/report`

When an OSINT seed arrives, Burp:
1. stores and renders the seed in the `BLANCHE` tab
2. attempts to run the local OSINT CLI automatically
3. ingests the resulting OSINT report back into the same tab

The Burp tab exposes:
- browser export views
- OSINT seed view
- OSINT summary view
- OSINT findings view
- OSINT raw JSON view

## Local CLI

Build the CLI:

```powershell
npm run build:osint
```

Manual examples:

```powershell
node .\osint-orchestrator\dist\cli.js --target example.com --output-dir .\tmp\osint
node .\osint-orchestrator\dist\cli.js --seed-file .\seed.json --output-dir .\tmp\osint
```

Current collectors:
- built-in DNS collector
- built-in HTTP collector
- built-in TLS collector
- optional passive wrappers for `subfinder`, `assetfinder`, `amass`, `gau`, and `waybackurls`

## Guardrails

- Findings are informational only.
- Missing external tools are represented as skipped, not as absence of public data.
- The generated markdown and JSON are intended to support report preparation and follow-on test planning.
