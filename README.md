# Web/API Security Assessment — OWASP Juice Shop

A full black-box web and API penetration test of OWASP Juice Shop (a deliberately
vulnerable application maintained by OWASP for security training), conducted as a
self-authorized portfolio project following a professional pentest workflow:
scoping and authorization → reconnaissance → structured testing across the OWASP
Top 10 → evidence-backed findings with CVSS/CWE mapping and remediation guidance.

**14 confirmed findings** — 5 Critical, 5 High, 1 Medium, 3 Low — covering
authentication, authorization, injection (SQL & NoSQL), XSS, API-specific abuse
(mass assignment, missing RBAC), security misconfiguration, and information
disclosure.

## Start here

- **[summary.md](summary.md)** — full findings table, severity breakdown, and
  cross-finding analysis
- **[scope-and-authorization.md](scope-and-authorization.md)** — engagement
  scope, rules of engagement, and self-authorization record
- **[attack-surface-map.md](attack-surface-map.md)** — recon methodology and
  endpoint inventory that testing was scoped from
- **[methodology-tracking-log.md](methodology-tracking-log.md)** — full testing
  log, verification standard applied to every finding, and open follow-up items

## Highlighted findings

| ID | Finding | Severity | Why it matters |
|---|---|---|---|
| [F-013](findings/F-013-mass-assignment-admin-registration.md) | Mass assignment on registration | Critical | Any anonymous visitor becomes a fully-privileged admin with one extra JSON field on public signup — no injection, no forged token, no existing account needed |
| [F-007](findings/F-007-sqli-full-database-extraction.md) | UNION-based SQL injection | Critical | Full user credential database extracted through a public search bar |
| [F-002](findings/F-002-jwt-alg-none-account-takeover.md) | JWT `alg:none` bypass | Critical | Unsigned, hand-forged tokens accepted as valid — full account takeover for any guessed user ID |
| [F-005](findings/F-005-idor-unauthorized-checkout.md) | IDOR on checkout | Critical | Any user can force checkout of another user's basket, and attach another user's saved card/address to their own order |
| [F-014](findings/F-014-unauthenticated-order-pdf-disclosure.md) | Order PDF disclosure via directory listing | High | Customer order receipts exposed with zero authentication, no guessing required |

Full list of all 14 findings, with severity and OWASP/CWE mapping, in
[summary.md](summary.md).

## Methodology

Testing followed a structured roadmap across nine phases: authentication and
session handling, authorization/IDOR, injection, XSS, API-specific abuse,
business logic, file upload/SSRF, security misconfiguration, and outdated
components. Every finding in this assessment was held to an explicit
verification standard before being marked confirmed — see Section 0 of
[methodology-tracking-log.md](methodology-tracking-log.md) — requiring raw
request/response evidence, a negative-control baseline where relevant,
reproducibility, and severity tied to actual demonstrated impact rather than
theoretical concern. Several negative results (confirmed non-vulnerabilities)
are documented alongside the positive findings, since knowing what *isn't*
exploitable is part of a credible assessment.

## Tooling

Burp Suite Community Edition (proxy/Repeater), browser DevTools, curl, and
manual JWT construction/decoding.

## Scope note

This assessment targets a local, self-hosted instance of OWASP Juice Shop
only — see [scope-and-authorization.md](scope-and-authorization.md) for the
full authorization record and rules of engagement. No public or third-party
systems were tested.

---

*OWASP Juice Shop is an intentionally vulnerable application distributed by
OWASP under the MIT license for security training and tool evaluation. All
findings in this repository describe known, intentional training
vulnerabilities in that application — not undisclosed vulnerabilities in
production software — which is why CWE (rather than CVE) is used throughout
for classification.*
