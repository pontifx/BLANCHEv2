# Burp Extension Scaffold

This Burp extension ingests both Chromium browser exports and BLANCHE OSINT seed/report payloads.

Current status:
- Gradle Kotlin DSL project structure is in place.
- The extension entrypoint registers a custom Burp suite tab named `BLANCHE`.
- The extension registers proxy-native ingest bridges for:
  - `http://blanche.invalid/ingest`
  - `http://blanche.invalid/osint/seed`
  - `http://blanche.invalid/osint/report`
- The extension also starts loopback ingest bridges for:
  - `http://127.0.0.1:47625/api/blanche/ingest`
  - `http://127.0.0.1:47625/api/blanche/osint/seed`
  - `http://127.0.0.1:47625/api/blanche/osint/report`
- The custom tab can load JSON from disk or accept automatic POSTs and render:
  - browser export summary/artifacts/storage/blob provenance/raw JSON
  - OSINT seed
  - OSINT summary
  - OSINT findings
  - OSINT raw JSON
- Ingested pages are added to the Burp site map, and pages with Chromium-only observations are highlighted in cyan with a managed `BLANCHE` annotation note.
- When an OSINT seed arrives, the extension attempts to run the local `osint-orchestrator/dist/cli.js` automatically if it can resolve that CLI path.
- The UI is intentionally basic and marked with TODOs where richer Burp-native views should replace text areas.

Known gaps:
- The default automatic handoff path depends on the browser actually being configured to proxy traffic through Burp, so that `http://blanche.invalid/ingest` is seen by Burp.
- The default host uses the reserved `.invalid` TLD to avoid the simple-hostname behavior that can bypass proxies on some systems.
- If the proxy-native handoff does not land, the Chromium side can fall back to the loopback bridge automatically for both browser exports and OSINT seeds.
- Automatic Burp-side OSINT execution depends on Node being available and the built CLI being discoverable, either in the repo-local default path or through `BLANCHE_OSINT_CLI`.
- A Gradle wrapper is not committed yet; the repo currently uses `scripts/build-burp.ps1` for local builds.
- The Swing UI is a scaffold, not a final operator workflow.
