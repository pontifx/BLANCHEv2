# BLANCHE OSINT Orchestrator

This package provides a local, passive OSINT orchestration CLI that can accept a Chromium-derived seed or a manual target.

Current built-in collectors:
- public DNS metadata
- public HTTP surface checks
- public TLS certificate metadata
- optional wrappers for passive open-source tools already on PATH:
  - `subfinder`
  - `assetfinder`
  - `amass` passive mode
  - `gau`
  - `waybackurls`

Usage:

```powershell
npm run build:osint
node .\osint-orchestrator\dist\cli.js --target example.com --output-dir .\tmp\osint
node .\osint-orchestrator\dist\cli.js --seed-file .\seed.json --output-dir .\tmp\osint
```

Guardrails:
- public and passive collection only
- informational output only
- no exploitation, validation, or severity assignment
- no attempt to replace existing testing workflows
