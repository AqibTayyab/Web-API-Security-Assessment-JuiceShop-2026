# Finding F-009: DOM-Based Cross-Site Scripting via Search Query Parameter

| Field | Value |
|---|---|
| Finding ID | F-009 |
| Title | DOM-Based XSS in Search Results Rendering (`bypassSecurityTrustHtml` Misuse) |
| Category | OWASP Top 10 — A03:2021 Injection (XSS) |
| Severity | High |
| CVSS 3.1 (estimated) | 8.2 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| Status | Confirmed |
| Affected Component | `GET /#/search?q=` — client-side search results rendering |
| Date Identified | 2026-09-29 |

## Summary

The search feature's results-rendering logic injects the `q` query parameter into the DOM in a context that bypasses Angular's default output sanitization, rather than relying on Angular's normal (safe) string interpolation. Submitting an `<iframe>` payload with a `javascript:` URI as the search query causes the payload to execute immediately in the browser upon loading the URL — no form submission, no additional interaction beyond visiting a link.

This was tested alongside a negative control: the review `message` field (see F-008-adjacent testing) was confirmed to properly HTML-escape a `<script>` payload with no execution. This search endpoint, by contrast, does execute injected markup — confirming the application's sanitization is inconsistent across components rather than uniformly absent or uniformly present, which is itself a useful root-cause observation.

## Steps to Reproduce

1. Ensure no special session state is required — this is reachable pre- and post-authentication.
2. Navigate to the following URL directly in a browser (address bar, or via a link sent to a victim):
   ```
   http://localhost:3000/#/search?q=<iframe src="javascript:alert(`XSS-POC-F009`)">
   ```
3. Observe the page executes the payload immediately on load — no further clicks, form submission, or search button press required.

## Evidence

**Payload used:**
```
<iframe src="javascript:alert(`XSS-POC-F009`)">
```

**Full URL tested:**
```
http://localhost:3000/#/search?q=<iframe src="javascript:alert(`XSS-POC-F009`)">
```

**Result:** JavaScript alert box fired in the browser, displaying `XSS-POC-F009` — confirming arbitrary script execution in the page's origin.

**Negative control (for contrast — see review-field testing):** the same class of payload (`<script>alert('...')</script>`) submitted via `PUT /rest/products/1/reviews` in the `message` field was stored (`201 Created`) but rendered as inert, HTML-escaped literal text on the product page — no execution. This confirms the vulnerability is specific to the search-results rendering path, not a blanket lack of output encoding across the application.

Full evidence (screenshot/browser confirmation) to be saved in
`evidence/requests-responses/F-009-dom-xss-search.txt` (or equivalent screenshot file per project convention).

*(Sanitization note: no real user data or credentials are involved in this payload — safe to commit as-is.)*

## Impact

- **Reflected/DOM-based XSS requiring only a link click** — no authentication, no stored payload, no prior account needed by the attacker. This is exploitable against any visitor, authenticated or not.
- Because the vulnerable data flows entirely through the URL and is processed client-side, this is trivially deliverable via phishing email, malicious ad, QR code, or shortened link — the victim need only load the URL.
- Arbitrary JavaScript execution in the site's origin means an attacker can, at minimum: steal the JWT from local storage/cookies (compounding **F-001**, which found sensitive data embedded in the JWT payload itself), perform actions as the victim (basket manipulation, profile changes), deface the page, or redirect the victim to an attacker-controlled site.
- Chained with **F-002** (JWT `alg:none` bypass) and **F-001** (sensitive JWT contents), a successful XSS pop here could allow an attacker to exfiltrate a victim's real token directly from the browser, rather than needing to forge one — turning a client-side bug into a full account-takeover delivery mechanism.
- Rated **High** rather than Critical because exploitation requires the victim to click a crafted link (`UI:R` in the CVSS vector) — it is not exploitable purely server-side or without any victim interaction, unlike F-002/F-005/F-006/F-007.
- **Confirmed via direct testing:** the root document (`GET /`) — which bootstraps the Angular SPA and every client-side route including the vulnerable `/#/search` page — serves **no `Content-Security-Policy` header at all**. A restrictive CSP (e.g., one disallowing inline script execution and `eval`) would have provided a meaningful defense-in-depth barrier against this exploit even with the underlying sanitization-bypass bug present. Its complete absence on the route where this XSS actually fires means the vulnerability has no secondary layer of protection at all. (Note: `/profile`, a separate, server-rendered, unrelated route, does carry its own narrow CSP scoped to that page — `img-src 'self' /assets/public/images/uploads/default.svg; script-src 'self' 'unsafe-eval'` — confirming CSP is applied inconsistently on a per-route basis rather than app-wide, and that even where present it permits `'unsafe-eval'`, a directive known to weaken CSP's effectiveness against many injection techniques.)

## Root Cause

The search-results component almost certainly uses Angular's `DomSanitizer.bypassSecurityTrustHtml()` (or equivalent) to render the search term with highlighting/bold-matching applied to results — a common pattern for "your search matched this text" UI. Using `bypassSecurityTrustHtml` explicitly tells Angular to skip its normal sanitization for that value, which is safe only if the developer independently guarantees the string cannot contain attacker-controlled markup. Here, the raw, unsanitized `q` parameter is passed into that trusted-HTML context directly, reintroducing exactly the risk Angular's framework-level protections are designed to prevent.

This stands in direct contrast to the review `message` field, which is rendered via Angular's default (safe) string interpolation and is therefore correctly escaped — demonstrating the vulnerability here is a specific, local misuse of a sanitization-bypass API, not a global framework misconfiguration.

## Remediation

1. **Do not use `bypassSecurityTrustHtml` (or equivalent trust-bypass APIs) on any value derived from user input**, including URL query parameters, without first passing that value through a dedicated HTML-sanitization library (e.g., DOMPurify) that strips executable markup while preserving safe formatting.
2. If search-term highlighting is the actual requirement, implement it via safe DOM APIs (e.g., splitting/wrapping matched substrings as text nodes with a CSS class) rather than HTML string construction, eliminating the need for a trust bypass at all.
3. Audit the codebase for **every** other use of `bypassSecurityTrustHtml`, `bypassSecurityTrustResourceUrl`, `bypassSecurityTrustScript`, and similar Angular sanitizer-bypass APIs — this is very likely not the only instance, and each one is a candidate for the same bug class.
4. **Add a Content-Security-Policy (CSP) header, applied app-wide (not just to isolated routes like `/profile`),** restricting `script-src` and disallowing inline script/`javascript:` URIs, as a defense-in-depth compensating control which would have prevented this specific payload from executing even if the underlying code issue persisted. Confirmed testing shows the root document currently ships no CSP at all, and the one CSP instance found elsewhere in the app (`/profile`) includes `'unsafe-eval'`, which should be avoided in any new policy — a permissive policy provides materially less protection than a strict one.
5. Add automated regression tests that load the search page with known XSS payloads in the `q` parameter and assert no script execution occurs (e.g., via headless-browser testing, not just API-response inspection — this bug is invisible to a pure API test since the vulnerable logic is entirely client-side).

## Related Findings

- **F-008** (NoSQL Type Confusion in Reviews) — both findings originated from the same broader "test input validation and output handling across the app" phase; F-008 found a storage/display-layer validation gap, this finding found a rendering-layer sanitization gap — different mechanisms, same overall theme of inconsistent input/output handling.
- **F-001** (Sensitive Data Exposure via JWT) — compounds this finding's impact, since a successful XSS execution could be used to exfiltrate the victim's real JWT (including the embedded password hash and deluxe token) directly from browser storage.
- **F-002** (JWT `alg:none` Account Takeover) — this finding provides a plausible *delivery mechanism* for capturing a legitimate victim token to use in impersonation, rather than needing to forge one from a guessed user ID.

## Follow-Up Testing (planned)

- [ ] Test whether the same payload works pre-authentication (fully logged-out session) to confirm no auth state affects exploitability.
- [ ] Audit other client-side routes/components for the same `bypassSecurityTrustHtml` pattern (e.g., product description rendering, track-order page).
- [x] Test whether a CSP header is present at all currently — **confirmed absent** on the root document (`GET /`), which governs the vulnerable `/#/search` route; see Impact section above. A dedicated, standalone "Missing/Inconsistent Security Headers" finding covering this alongside the other header gaps noted in `attack-surface-map.md` Section 5 (missing HSTS, deprecated `Feature-Policy`) is recommended as a follow-up item for the overall report, since this issue extends beyond just the search page.
- [ ] Test cookie/localStorage exfiltration proof-of-concept (e.g., `document.cookie` read, or reading the JWT from storage) to demonstrate concrete session-theft impact beyond a bare `alert()`, if within project scope/rules of engagement.

## References

- OWASP Top 10 2021 — A03: Injection
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- Angular Security Guide — https://angular.io/guide/security
