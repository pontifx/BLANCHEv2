# BLANCHE OSINT Summary

Generated: 2026-09-24T17:17:37.190Z
Primary Hostname: www.wellsfargo.com
Target URL: https://www.wellsfargo.com

## Narrative

Public OSINT summary for www.wellsfargo.com

Collected 11 informational findings for www.wellsfargo.com. The strongest current themes are dns-record (6), document-reference (2), http-surface (1). Completed tools: 3; skipped tools: 0.

## Follow-On Focus

- No public security.txt contact was observed; plan coordination channels separately.
- Use public technology hints to prioritize manual review paths, not to infer vulnerabilities.

## Report-Ready Notes

- This output is informational OSINT only and does not validate vulnerabilities or business impact.
- Skipped tools usually indicate local environment gaps rather than absence of public data.
- Counts and summaries should be used to prioritize manual testing, not replace it.

## Tool Executions

- Built-in DNS Collector [completed] target=wellsfargo.com outputs=6
- Built-in HTTP Surface Collector [completed] target=www.wellsfargo.com outputs=4
- Built-in TLS Collector [completed] target=www.wellsfargo.com outputs=1

## Findings

- [dns-record] DNS A records for www.wellsfargo.com: Public DNS resolution returned A data for www.wellsfargo.com. (target: www.wellsfargo.com)
- [dns-record] DNS CNAME records for www.wellsfargo.com: Public DNS resolution returned CNAME data for www.wellsfargo.com. (target: www.wellsfargo.com)
- [dns-record] DNS MX records for wellsfargo.com: Public DNS resolution returned MX data for wellsfargo.com. (target: wellsfargo.com)
- [dns-record] DNS NS records for wellsfargo.com: Public DNS resolution returned NS data for wellsfargo.com. (target: wellsfargo.com)
- [dns-record] DNS TXT records for wellsfargo.com: Public DNS resolution returned TXT data for wellsfargo.com. (target: wellsfargo.com)
- [dns-record] DNS SOA records for wellsfargo.com: Public DNS resolution returned SOA data for wellsfargo.com. (target: wellsfargo.com)
- [http-surface] Public web surface for https://www.wellsfargo.com/: The target returned a public web response that can guide scope familiarization. (target: https://www.wellsfargo.com/)
- [technology-hint] Public technology hints for www.wellsfargo.com: The public landing page exposed response headers or HTML metadata that can guide follow-on review. (target: www.wellsfargo.com)
- [document-reference] robots.txt observations for www.wellsfargo.com: Public crawler policy and referenced sitemap hints were collected from robots.txt. (target: www.wellsfargo.com)
- [document-reference] Public sitemap reference for www.wellsfargo.com: A public sitemap was discoverable and can be used to widen page-level OSINT review. (target: www.wellsfargo.com)
- [tls-certificate] TLS certificate metadata for www.wellsfargo.com: The target exposed certificate metadata on TCP/443 that can reveal related names and issuance details. (target: www.wellsfargo.com)
