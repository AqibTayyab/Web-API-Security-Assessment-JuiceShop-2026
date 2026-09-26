# Attack Surface Map — OWASP Juice Shop

> Status: COMPLETED — built from actual Burp Suite proxy history (347 in-scope
> requests to `localhost`, filtered from an 817-request raw capture; 265 Google
> requests and 49+ Mozilla telemetry requests were excluded as out of scope per
> `scope-and-authorization.md`, since the browser proxy captured background
> traffic from the whole browser, not just the Juice Shop tab).

Recon date: 2026-09-25/26 (per Burp export timestamps).
Tooling: Burp Suite Community 2026.3.3, browser-proxied traffic capture.

---

## 1. User Roles

| Role | How obtained | Notes |
|---|---|---|
| Anonymous / guest | Default | Can browse `/`, `/api/Products`, product reviews |
| Registered customer | `/#/register` → session via `POST /rest/user/login` | Confirmed — auth flow captured |
| Admin | Not yet reached in this capture | To be pursued in Step 4 (vertical privilege escalation testing) |

Two test accounts should still be created (User A / User B) if not already, for the
authorization/IDOR testing phase.

## 2. Authentication Surface

| Feature | Endpoint | Method | Notes |
|---|---|---|---|
| Login | `/rest/user/login` | POST | Returns session artifact — see Section 6 |
| Current session check | `/rest/user/whoami` | GET | Called repeatedly (3x) — likely on every route change |
| Session mechanism | Cookie `token` + `Authorization` header both observed | — | **Needs clarification in testing**: app sends both a `token` cookie and an `Authorization` header — worth checking in Step 4 whether *either alone* is sufficient (could indicate inconsistent enforcement) |
| Password/account recovery | Not captured in this session | — | Revisit manually — browse to "forgot password" and recapture |

## 3. User-Facing Functions (confirmed from traffic)

| Feature | Endpoint(s) | Method | Notes |
|---|---|---|---|
| Product listing/detail | `/api/Products/1` | GET | Numeric sequential ID → IDOR candidate |
| Product search | `/rest/products/search` | GET | Injection candidate |
| Product reviews (view) | `/rest/products/<id>/reviews` | GET | Seen for 15+ different product IDs |
| Product reviews (submit/edit) | `/rest/products/1/reviews`, `/rest/products/41/reviews` | PUT | **Notable**: reviews are edited via PUT with no visible review-ownership ID in the path — strong candidate for "can User A edit User B's review" (broken access control) |
| Basket | `/rest/basket/0`, `/rest/basket/6`, `/rest/basket/NaN` | GET | Numeric basket ID in URL → IDOR candidate (can User A view basket ID belonging to User B?). Note: a request to `/rest/basket/NaN` also appeared — worth checking how the app handled a non-numeric ID |
| Add to basket | `/api/BasketItems/` | POST | |
| Checkout | `/rest/basket/6/checkout` | POST | Business logic target — check price/quantity tampering here in Step 4 |
| Order history | `/rest/order-history` | GET | Check whether it's scoped to the logged-in user only |
| Order tracking | `/rest/track-order/1aed-39a856bbd2a43b23`, `/rest/track-order/1aed-fb48b7bb983858c8` | GET | Two different order tracking IDs captured — **candidate for enumeration/IDOR**: are these IDs guessable/sequential enough to enumerate other users' orders? |
| Wallet | `/rest/wallet/balance` | GET | Business logic target |
| Deluxe membership | `/rest/deluxe-membership` | GET (400), POST (200) | Payment/business logic target — GET returning 400 is itself worth understanding (state-dependent?) |
| Profile view/edit | `/profile` | GET (500!), POST | **Notable**: `GET /profile` returned HTTP 500 in this capture — an unhandled server error is worth deliberately reproducing; error messages can leak stack traces/internals |
| Profile image upload (file) | `/profile/image/file` | POST | File upload — validate file type/size handling in Step 4 |
| Profile image upload (URL) | `/profile/image/url` | POST | **Notable**: fetching an image by URL server-side is a classic **SSRF candidate** — flag this for dedicated testing |
| Complaint form (file upload) | `/api/Complaints/` | POST (500) | Returned 500 in this capture — reproduce deliberately, check what broke |
| Payment cards | `/api/Cards`, `/api/Cards/7` | GET, POST (500) | POST returned 500 — reproduce deliberately |
| Addresses | `/api/Addresss`, `/api/Addresss/7` | GET | (Note: app's own naming typo, "Addresss" — not yours) |
| Feedback | `/api/Feedbacks/` | GET | |

## 4. Administrative / Config Endpoints (found unauthenticated or lightly protected)

| Endpoint | Method | Notes |
|---|---|---|
| `/rest/admin/application-configuration` | GET | **Notable**: an "admin" path reachable in normal browsing — confirm in Step 4 whether this required admin auth or was reachable as a normal/anonymous user. If the latter, that's a real finding (broken access control / information disclosure) |
| `/rest/admin/application-version` | GET | Same as above — verify auth requirement |

## 5. Information Disclosure / Misconfiguration Candidates (already visible from recon alone)

These don't need "attacking" — they were sitting in plain HTTP responses during normal browsing:

| Observation | Evidence | Why it matters |
|---|---|---|
| Directory listing enabled on `/ftp/` | `GET /ftp/`, `/ftp/quarantine` returned 200 with file listings, exposing `acquisitions.md` (sounds like an internal business document) and several `.url` files pointing at "juicy_malware_*" filenames | Classic **sensitive file exposure / directory listing** finding |
| `X-Recruiting: /#/jobs` response header on every page | Seen on `/`, `/api/Products/1`, `/rest/basket/6`, `/rest/user/whoami` | Minor info disclosure — custom header unrelated to app function, leaks internal routing |
| `Access-Control-Allow-Origin: *` on API responses | Seen on all sampled API responses | **CORS misconfiguration candidate** — wildcard CORS on authenticated endpoints can allow cross-origin data theft; worth checking whether this applies to authenticated requests too |
| Missing `Content-Security-Policy` header | Not present in any sampled response | Increases impact of any XSS found later |
| Missing `Strict-Transport-Security` header | Not present | Expected on plain local HTTP, but worth noting as a header-hardening gap in the report |
| `Feature-Policy` used instead of `Permissions-Policy` | Seen on all responses | `Feature-Policy` is deprecated — minor finding |
| `GET /profile` → HTTP 500 | Captured directly | Needs reproduction — unhandled errors can leak stack traces |
| `POST /api/Cards/` → HTTP 500 | Captured directly | Needs reproduction |
| `POST /api/Complaints/` → HTTP 500 | Captured directly | Needs reproduction — this is the file upload form, so worth checking if a malformed upload triggers it |

## 6. Parameters, Cookies, and Tokens Observed

| Name | Where | Notes |
|---|---|---|
| `token` | Cookie | Session cookie — flags not yet checked (HttpOnly/Secure/SameSite) — confirm in Burp's Cookie Jar or response `Set-Cookie` line in Step 4 |
| `Authorization` | Request header | Sent alongside the `token` cookie — decode the value structure (if JWT) offline via jwt.io in Step 4; do not commit the raw value anywhere |
| `X-User-Email` | Request header (custom, non-standard) | **Notable** — not a standard header; something in the app is setting a user's email as a request header. Worth tracing which feature sends this and whether it's trusted server-side without verification (could indicate an auth-bypass style bug — attacker-controlled identity header) |
| `continueCode`, `continueCodeFindIt`, `continueCodeFixIt` | Cookies | These are Juice Shop's own internal "hacking challenge progress" cookies — not a vulnerability, just how the app tracks tutorial progress. Exclude these from findings, they're app scaffolding, not a bug |
| `id` (numeric, in many paths) | `/api/Products/{id}`, `/rest/basket/{id}`, `/rest/track-order/{id}` | Sequential/short IDs — primary IDOR test surface for Step 4 |

## 7. Real-Time / Other

| Item | Notes |
|---|---|
| `/socket.io/` | 129 requests (37 POST, 92 GET) — WebSocket/long-polling channel. Out of scope for classic HTTP testing but worth a quick manual check for whether it leaks data cross-user (e.g., live chat/notifications feature in Juice Shop) |
| `/robots.txt` | Captured — check contents for disallowed paths that hint at hidden functionality |
| Static assets (JS chunks, SVGs, fonts, CSS) | ~90 requests, excluded from this table — not attack surface, purely front-end assets |

## 8. Sensitive Actions — Priority List for Authorization Testing (Step 4)

Ranked by how promising they look from recon alone:

1. **`PUT /rest/products/<id>/reviews`** — can User A edit User B's review?
2. **`GET /rest/basket/<id>`** — can User A view User B's basket by changing the ID?
3. **`GET /rest/track-order/<code>`** — are order tracking codes guessable/enumerable?
4. **`GET /rest/admin/application-configuration`** — does this need admin auth at all?
5. **`POST /profile/image/url`** — SSRF: does the server fetch attacker-supplied URLs unrestricted?
6. **`X-User-Email` header** — is a user's identity trusted from a client-supplied header anywhere?

---

## Still To Do Before Step 4

- [ ] Capture the "forgot password" flow (not in this recon session)
- [ ] Confirm whether an admin account/role was ever reached — if not, discovering
      admin access is itself an objective for Step 4
- [ ] Check `Set-Cookie` flags on the `token` cookie (HttpOnly/Secure/SameSite)
- [ ] Decode the `Authorization` token structure (offline, never commit the raw value)
