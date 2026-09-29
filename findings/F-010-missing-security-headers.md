# Finding F-010: Missing and Inconsistent Security Headers (CSP, Feature-Policy, HSTS)

| Field | Value |
|---|---|
| Finding ID | F-010 |
| Title | Missing Application-Wide Content-Security-Policy, Deprecated `Feature-Policy` Header, and Absent `Strict-Transport-Security` |
| Category | OWASP Top 10 — A05:2021 Security Misconfiguration |
| Severity | Low |
| Status | Confirmed |
| Affected Component | Application-wide (all routes sampled); CSP specifically tested on `GET /` |
| Date Identified | 2026-09-29 |

## Summary

The application is missing or using outdated HTTP security headers across the board. Most significantly, the root document (`GET /`) — which bootstraps the entire Angular single-page application, including every client-side route such as the vulnerable search page documented in **F-009** — serves **no `Content-Security-Policy` header at all**. Where a CSP does exist elsewhere in the app (on the separate, server-rendered `/profile` page), it is scoped narrowly to that one route rather than applied consistently, and it permits `'unsafe-eval'`, a directive known to weaken CSP's effectiveness as a defense against script injection.

Additionally, the application sends `Feature-Policy` — a header deprecated in favor of `Permissions-Policy` since 2020 — on every sampled response, and does not send `Strict-Transport-Security` at all.

None of these issues are independently exploitable; they are **defense-in-depth gaps**. Their significance lies in what they fail to prevent, not in what they directly enable. This finding is scored Low individually, but its practical relevance is best understood in combination with **F-009**, where the complete absence of CSP on the exact route where a confirmed XSS vulnerability fires removed what would otherwise have been a meaningful secondary layer of protection.

## Steps to Reproduce

1. Send a plain, uncached `GET /` request (no `If-None-Match` header, to avoid a `304 Not Modified` response, which omits most headers):
   ```
   GET / HTTP/1.1
   Host: localhost:3000
   Accept: text/html
   Connection: keep-alive
   ```
2. Inspect the response headers. Observe `X-Content-Type-Options`, `X-Frame-Options`, and `Feature-Policy` are present, but `Content-Security-Policy` and `Strict-Transport-Security` are absent.
3. For comparison, send `GET /profile` (authenticated) and observe it **does** return a `Content-Security-Policy` header — but one scoped only to that page, and only that page.

## Evidence

**`GET /` response headers (root document — governs the entire SPA, including `/#/search`):**
```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Content-Type: text/html; charset=UTF-8
```
No `Content-Security-Policy` header present. No `Strict-Transport-Security` header present.

**`GET /profile` response headers (separate, server-rendered route — for contrast):**
```
HTTP/1.1 200 OK
Content-Security-Policy: img-src 'self' /assets/public/images/uploads/default.svg; script-src 'self' 'unsafe-eval'
```
A CSP is present here, but it is route-specific rather than applied globally, and its `script-src` directive includes `'unsafe-eval'`.

Full raw requests/responses saved in
`evidence/requests-responses/F-010-security-headers.txt`.

## Impact

- **No CSP on the route where confirmed XSS occurs.** As documented in **F-009**, the search page (`/#/search`) is served entirely from the root document's bootstrap, which carries no CSP. A well-configured CSP (e.g., restricting `script-src` to `'self'` and disallowing inline/`eval` execution) is one of the most effective defense-in-depth controls against XSS — its total absence here means F-009's vulnerability has no secondary safety net at all.
- **Inconsistent application of security controls.** The fact that `/profile` has a CSP but the SPA root does not indicates security headers are being set ad hoc, per-route, rather than through a centralized, application-wide policy — a pattern that tends to produce exactly this kind of gap and is worth flagging as a process observation, not just a technical one.
- **`'unsafe-eval'` in the one CSP that does exist** undermines its own effectiveness; many real-world XSS payloads and injected libraries rely on `eval()`-based execution, which this directive explicitly permits.
- **Deprecated `Feature-Policy` header** provides no meaningful protection in modern browsers, which have moved to `Permissions-Policy`; this is a minor hygiene issue rather than an active risk.
- **Missing `Strict-Transport-Security`** is expected and low-risk in this specific local/`localhost` testing context (plain HTTP, no TLS), but is flagged here as a gap that would need addressing before any production/public deployment.

## Root Cause

Security headers appear to be configured manually and inconsistently per-route (e.g., a CSP was added specifically to the profile page's server-rendered HTML but not to the application's main entry point), rather than through a single, centralized security-headers middleware applied to all responses. No headers-hardening library (e.g., `helmet` for Express/Node.js, which Juice Shop is built on) appears to be configured with a CSP directive at all for the SPA-serving route.

## Remediation

1. **Configure a strict, application-wide Content-Security-Policy** via centralized middleware (e.g., `helmet.contentSecurityPolicy()` if using Express/`helmet`) applied to all responses, not just individual routes. At minimum: `script-src 'self'` with no `'unsafe-eval'` or `'unsafe-inline'`, and `object-src 'none'`.
2. **Remove `'unsafe-eval'`** from the existing `/profile` CSP once a suitable alternative to whatever library requires it is identified, or scope it out if it is no longer needed.
3. **Replace `Feature-Policy` with `Permissions-Policy`**, using the modern header syntax, across all responses.
4. **Add `Strict-Transport-Security`** ahead of any production or externally-reachable deployment of this application (not required for pure local/loopback testing, but should not be forgotten before going live).
5. Apply all of the above through one shared middleware layer so headers are guaranteed consistent across every route by default, rather than requiring each new route to remember to set them individually.

## Related Findings

- **F-009** (DOM-Based XSS via Search Query Parameter) — this finding's most direct practical relevance: the confirmed absence of CSP on the exact route where F-009's XSS fires removed a defense-in-depth control that could have mitigated or blocked that exploit even with the underlying sanitization bug present.

## References

- OWASP Top 10 2021 — A05: Security Misconfiguration
- CWE-693: Protection Mechanism Failure
- OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/
- MDN — Content-Security-Policy — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
