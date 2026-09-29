# Findings Summary — OWASP Juice Shop Web/API Security Assessment

| ID | Name | Severity | OWASP Top 10 (2021) | CWE |
|---|---|---|---|---|
| [F-001](findings/F-001-sensitive-data-exposure-jwt.md) | Sensitive Data Exposure via JWT Payload | High | A02: Cryptographic Failures | CWE-522, CWE-200 |
| [F-002](findings/F-002-jwt-alg-none-account-takeover.md) | JWT Signature Verification Bypass (`alg:none`) — Account Takeover | Critical | A07: Identification & Authentication Failures | CWE-347 |
| [F-003](findings/F-003-unauthenticated-admin-config.md) | Unauthenticated Access to Admin Configuration Endpoint | High | A01: Broken Access Control | CWE-306 |
| [F-004](findings/F-004-review-injection-corrected.md) | Review Author Field Client-Controlled (Spoofing) + Orphaned Reviews | Medium | A04: Insecure Design | CWE-20 |
| [F-005](findings/F-005-idor-unauthorized-checkout.md) | IDOR on Checkout — Unauthorized Checkout of Another User's Basket | Critical | A01: Broken Access Control | CWE-639 |
| [F-006](findings/F-006-sqli-admin-login-bypass.md) | SQL Injection Authentication Bypass — Admin Login | Critical | A03: Injection | CWE-89 |
| [F-007](findings/F-007-sqli-full-database-extraction.md) | Full User Database Extraction via UNION-Based SQL Injection | Critical | A03: Injection | CWE-89 |
| [F-008](findings/F-008-nosql-type-confusion-reviews.md) | NoSQL Operator/Type Confusion in Review Submission | Low | A03: Injection / A04: Insecure Design | CWE-20, CWE-943 |
| [F-009](findings/F-009-dom-xss-search-query.md) | DOM-Based XSS via Search Query Parameter | High | A03: Injection | CWE-79 |

## Severity Breakdown

| Severity | Count | Findings |
|---|---|---|
| Critical | 4 | F-002, F-005, F-006, F-007 |
| High | 3 | F-001, F-003, F-009 |
| Medium | 1 | F-004 |
| Low | 1 | F-008 |

## Notes

- No CVE identifiers are assigned to these findings. CVEs are issued for
  undisclosed vulnerabilities in real, deployed software; OWASP Juice Shop's
  bugs are intentional, documented training challenges rather than disclosed
  vulnerabilities, so CWE (Common Weakness Enumeration) classification is the
  correct and standard reference system here instead.
- F-002 and F-005 share a related theme (both stem from insufficient
  server-side verification of client-supplied identity/ownership data) but
  are independent bugs — fixing one does not resolve the other.
- F-006 and F-007 share the same root cause (raw SQL string concatenation)
  across two independent endpoints (`/rest/user/login` and
  `/rest/products/search`) and should be read together as one systemic
  injection pattern rather than two unrelated bugs.
- F-004 and F-008 both stem from the same underlying gap — the review
  submission endpoint (`PUT /rest/products/:id/reviews`) performing no
  request-body schema validation at all — surfaced through two independent
  symptoms (identity spoofing/orphaned records, and type confusion,
  respectively).
- F-009 is a client-side (Angular) sanitization-bypass bug, distinct in
  mechanism from F-006/F-007 (server-side SQL injection) and F-008
  (server-side NoSQL type confusion), despite all four falling under the
  same OWASP A03: Injection category.
- Full methodology, scope, and rules of engagement are documented in
  `scope-and-authorization.md`. Recon methodology is documented in
  `attack-surface-map.md`.
