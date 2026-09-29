# Findings Summary — OWASP Juice Shop Web/API Security Assessment

| ID | Name | Severity | OWASP Top 10 (2021) | CWE |
|---|---|---|---|---|
| [F-001](findings/F-001-sensitive-data-exposure-jwt.md) | Sensitive Data Exposure via JWT Payload | High | A02: Cryptographic Failures | CWE-522, CWE-200 |
| [F-002](findings/F-002-jwt-alg-none-account-takeover.md) | JWT Signature Verification Bypass (`alg:none`) — Account Takeover | Critical | A07: Identification & Authentication Failures | CWE-347 |
| [F-003](findings/F-003-unauthenticated-admin-config.md) | Unauthenticated Access to Admin Configuration Endpoint | High | A01: Broken Access Control | CWE-306 |
| [F-004](findings/F-004-review-injection-corrected.md) | Review Author Field Client-Controlled (Spoofing) + Orphaned Reviews | Medium | A04: Insecure Design | CWE-20 |
| [F-005](findings/F-005-idor-unauthorized-checkout.md) | IDOR on Checkout — Unauthorized Checkout of Another User's Basket (+ paymentId/addressId sub-finding) | Critical | A01: Broken Access Control | CWE-639 |
| [F-006](findings/F-006-sqli-admin-login-bypass.md) | SQL Injection Authentication Bypass — Admin Login | Critical | A03: Injection | CWE-89 |
| [F-007](findings/F-007-sqli-full-database-extraction.md) | Full User Database Extraction via UNION-Based SQL Injection | Critical | A03: Injection | CWE-89 |
| [F-008](findings/F-008-nosql-type-confusion-reviews.md) | NoSQL Operator/Type Confusion in Review Submission | Low | A03: Injection / A04: Insecure Design | CWE-20, CWE-943 |
| [F-009](findings/F-009-dom-xss-search-query.md) | DOM-Based XSS via Search Query Parameter | High | A03: Injection | CWE-79 |
| [F-010](findings/F-010-missing-security-headers.md) | Missing/Inconsistent Security Headers (CSP, Feature-Policy, HSTS) | Low | A05: Security Misconfiguration | CWE-693 |
| [F-011](findings/F-011-verbose-sql-error-disclosure.md) | Verbose Database Error Disclosure on `/api/Cards/` and `/api/Complaints/` | Low | A05: Security Misconfiguration | CWE-209 |
| [F-012](findings/F-012-missing-rbac-rest-endpoints.md) | Missing RBAC on REST-Scaffolded Endpoints (`/api/Users`, `/api/Feedbacks`) | High | A01: Broken Access Control | CWE-862, CWE-863 |
| [F-013](findings/F-013-mass-assignment-admin-registration.md) | Mass Assignment on Registration Allows Self-Service Admin Account Creation | Critical | A08: Software and Data Integrity Failures | CWE-915 |
| [F-014](findings/F-014-unauthenticated-order-pdf-disclosure.md) | Unauthenticated Order Confirmation PDF Disclosure via `/ftp/` Directory Listing | High | A01: Broken Access Control / A05: Security Misconfiguration | CWE-306, CWE-548 |

## Severity Breakdown

| Severity | Count | Findings |
|---|---|---|
| Critical | 5 | F-002, F-005, F-006, F-007, F-013 |
| High | 5 | F-001, F-003, F-009, F-012, F-014 |
| Medium | 1 | F-004 |
| Low | 3 | F-008, F-010, F-011 |

**Total: 14 findings.**

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
- F-010 and F-011 both fall under A05: Security Misconfiguration and reflect
  the same overall theme — individually low-severity defense-in-depth and
  error-handling gaps rather than a single high-impact bug. F-010's absence
  of a CSP is most consequential in combination with F-009's XSS, since it
  removed a secondary layer of protection that could have blunted that
  exploit.
- F-012 and F-013 both concern the `/api/Users` and related REST-scaffolded
  endpoint family, but are independent root causes: F-012 is a missing
  authorization check on an *existing* record's data; F-013 is a missing
  field whitelist on *creating* a new record. Either one alone would allow
  serious compromise; together they show the same endpoint family has no
  consistent access-control or schema-validation discipline applied to it.
- F-013 is arguably the most severe and most directly exploitable finding in
  the assessment: it requires no injection, no forged token, and no prior
  account — a single extra field on public registration yields a genuine,
  fully-privileged admin session, confirmed via a real signed JWT obtained
  through the normal login flow.
- F-014 was discovered as a direct follow-on from Step 12 (outdated/
  vulnerable components) testing — a `.bak` file-extension bypass on the
  same `/ftp/` directory failed cleanly, but reviewing that same directory's
  contents surfaced two other customers' order confirmation PDFs, retrievable
  with zero authentication. It shares its root cause (missing authentication
  on a path that should require it) with F-003, and its delivery mechanism
  (directory listing) was already flagged as a lower-severity observation
  during initial recon (`attack-surface-map.md`, Section 5) before this
  finding proved it exposes customer-facing transactional data, not just
  internal business files.
- Full methodology, scope, and rules of engagement are documented in
  `scope-and-authorization.md`. Recon methodology is documented in
  `attack-surface-map.md`. Test status and open follow-up items across all
  findings are tracked in `methodology-tracking-log.md`.
