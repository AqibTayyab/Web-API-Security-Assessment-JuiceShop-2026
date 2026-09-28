# Findings Summary — OWASP Juice Shop Web/API Security Assessment

| ID | Name | Severity | OWASP Top 10 (2021) | CWE |
|---|---|---|---|---|
| [F-001](findings/F-001-sensitive-data-exposure-jwt.md) | Sensitive Data Exposure via JWT Payload | High | A02: Cryptographic Failures | CWE-522, CWE-200 |
| [F-002](findings/F-002-jwt-alg-none-account-takeover.md) | JWT Signature Verification Bypass (`alg:none`) — Account Takeover | Critical | A07: Identification & Authentication Failures | CWE-347 |
| [F-003](findings/F-003-unauthenticated-admin-config.md) | Unauthenticated Access to Admin Configuration Endpoint | High | A01: Broken Access Control | CWE-306 |
| [F-004](findings/F-004-review-injection-corrected.md) | Review Author Field Client-Controlled (Spoofing) + Orphaned Reviews | Medium | A04: Insecure Design | CWE-20 |
| [F-005](findings/F-005-idor-unauthorized-checkout.md) | IDOR on Checkout — Unauthorized Checkout of Another User's Basket | Critical | A01: Broken Access Control | CWE-639 |

## Severity Breakdown

| Severity | Count | Findings |
|---|---|---|
| Critical | 2 | F-002, F-005 |
| High | 2 | F-001, F-003 |
| Medium | 1 | F-004 |

## Notes

- No CVE identifiers are assigned to these findings. CVEs are issued for
  undisclosed vulnerabilities in real, deployed software; OWASP Juice Shop's
  bugs are intentional, documented training challenges rather than disclosed
  vulnerabilities, so CWE (Common Weakness Enumeration) classification is the
  correct and standard reference system here instead.
- F-002 and F-005 share a related theme (both stem from insufficient
  server-side verification of client-supplied identity/ownership data) but
  are independent bugs — fixing one does not resolve the other.
- Full methodology, scope, and rules of engagement are documented in
  `scope-and-authorization.md`. Recon methodology is documented in
  `attack-surface-map.md`.
