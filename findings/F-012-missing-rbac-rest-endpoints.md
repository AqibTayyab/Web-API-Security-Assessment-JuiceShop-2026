# Finding F-012: Missing Role-Based Access Control on REST-Scaffolded Endpoints

| Field | Value |
|---|---|
| Finding ID | F-012 |
| Title | Unrestricted Read of Full User Table and Unrestricted Delete of Any Feedback Record — No Role or Ownership Checks on Sequelize-Backed REST Endpoints |
| Category | OWASP Top 10 — A01:2021 Broken Access Control |
| Severity | High |
| Status | Confirmed |
| Affected Component | `GET /api/Users`, `DELETE /api/Feedbacks/:id` |
| Date Identified | 2026-09-29 |

## Summary

This finding began as an attempt to test whether a **forged** `alg:none` JWT with an escalated `"role":"admin"` claim could bypass role-based access control (a direct follow-up to the technique proven in **F-002**). The testing produced a more direct and, in some ways, more serious result than originally intended: **both endpoints tested succeeded using a completely genuine, unmodified, legitimately-issued `customer`-role token** — no token forgery was needed at all, because no role check exists on either endpoint in the first place.

- `GET /api/Users` returns the **entire user table** — every account's email, role, and (where populated) `deluxeToken` — to any authenticated user regardless of role.
- `DELETE /api/Feedbacks/:id` allows any authenticated user to **delete any feedback record by ID**, with no check that the record belongs to them or that their role permits deletion.

Both routes appear to be Sequelize's auto-generated REST scaffolding (`/api/<ModelName>/`), which — unlike the hand-written `/rest/*` routes elsewhere in the app — does not have role or ownership middleware applied. This is evidenced directly by contrast: `/api/Cards/:id`, a sibling route on the same auto-generated pattern, **does** correctly block cross-user access (returning `400 "Malicious activity detected"` when tested during related work — see Related Findings), showing that *some* Sequelize-scaffolded routes are protected while others in the same family are not.

## Investigation Notes (how this was found)

The original test plan was to forge an `alg:none` token with `"role":"admin"` (using the exact technique from F-002) and compare its behavior against a real, unmodified `customer` token on an admin-gated endpoint, to prove the forgery technique specifically defeats role checks. In execution:

1. **`GET /api/Users`** was tested with both a real customer token and the forged admin-role token as a baseline/comparison pair. Both returned **identical, full results** (`200 OK`, complete user table, 25 accounts). Since the baseline (unmodified token) already succeeded, the forgery test was inconclusive by design — there was no protection in place for the forged token to bypass.
2. **`DELETE /api/Feedbacks/1`** was tested the same way, expecting the real customer token to fail (establishing a baseline) before testing the forged version. Instead, the real customer token **succeeded outright** (`200 OK`, `{"status":"success","data":{}}`), deleting the record. The subsequent forged-token request against the same ID correctly returned `404 Not Found` — not because the forgery was rejected, but because the record had already been deleted by the prior, genuine-token request.

In both cases, the intended forgery test could not be completed because the endpoints were unprotected against ordinary, legitimate low-privilege accounts to begin with — a more fundamental gap than the one originally being tested for.

## Steps to Reproduce

**`GET /api/Users` (any authenticated user, any role):**
```
GET /api/Users HTTP/1.1
Host: localhost:3000
Authorization: Bearer <any valid customer-role token>
```
Observe `200 OK` with the complete `Users` table returned in the response body.

**`DELETE /api/Feedbacks/:id` (any authenticated user, any role):**
```
DELETE /api/Feedbacks/1 HTTP/1.1
Host: localhost:3000
Authorization: Bearer <any valid customer-role token>
```
Observe `200 OK`, `{"status":"success","data":{}}` — the record is deleted regardless of whether the requesting user created it or holds any elevated role.

## Evidence

**`GET /api/Users` — real customer token (User A, `id:25`, role `customer`), response excerpt:**
```
HTTP/1.1 200 OK
Content-Length: 6890

{"status":"success","data":[
  {"id":1,"email":"admin@juice-sh.op","role":"admin", ...},
  {"id":5,"email":"ciso@juice-sh.op","role":"deluxe","deluxeToken":"d715c2c75d4a42d3825a050e0a0163c1959b51165373f17bd8eed7b1e05bf20d", ...},
  {"id":15,"email":"accountant@juice-sh.op","role":"accounting", ...},
  {"id":25,"email":"test@gmail.com","role":"customer", ...}
  ... (25 accounts total)
]}
```

**Identical request with a forged `alg:none` / `"role":"admin"` token** returned byte-for-byte the same response (`Content-Length: 6890`, identical `ETag`), confirming the forged token contributed nothing beyond what the real token already permitted.

**`DELETE /api/Feedbacks/1` — real customer token:**
```
DELETE /api/Feedbacks/1 HTTP/1.1
Authorization: Bearer <User A's real, unmodified customer token>

HTTP/1.1 200 OK
{"status":"success","data":{}}
```

Full raw requests/responses saved in
`evidence/requests-responses/F-012-missing-rbac-rest-endpoints.txt`.

*(Sanitization note: the extracted `deluxeToken` values visible in the evidence should be truncated/redacted before committing, consistent with the handling already applied to similar sensitive fields in F-007's evidence.)*

## Impact

- **Complete user directory disclosure to any authenticated account**, including every user's role and, for `deluxe`-tier accounts, their `deluxeToken` — a credential-adjacent value that should never be exposed to any user other than its owner (or genuine admin). This is a smaller-scope repeat of F-007's impact (full user data exposure) but reachable without any SQL injection at all — a plain, unmodified low-privilege session is sufficient.
- **Unrestricted deletion of feedback records** by any authenticated user, regardless of authorship — a straightforward data-integrity and availability issue. An attacker (or any malicious/careless customer) could delete all feedback in the system, including reviews/complaints left by other genuine customers, with no ownership check preventing it.
- **Demonstrates the underlying REST-scaffolding pattern is inconsistently protected**: `/api/Cards/:id` blocks cross-user access, but `/api/Users` and `/api/Feedbacks/:id` do not — strongly suggesting role/ownership middleware was applied selectively, model-by-model, rather than as a consistent framework-level default. Any other `/api/<Model>/` route not yet tested should be treated as suspect until verified (see Follow-Up Testing).
- Rated **High** rather than Critical because, unlike F-006/F-007, this does not grant authentication bypass or direct credential extraction via injection — but the breadth of exposed data (every user's role and deluxe token) and the destructive write capability (arbitrary feedback deletion) place it well above a purely informational finding.

## Root Cause

Both routes are almost certainly auto-generated by Sequelize's REST API scaffolding (commonly exposed via a library such as `epilogue` or a hand-rolled equivalent, given the Sequelize/SQLite backend already confirmed via F-006/F-007/F-011) without any authorization middleware layered on top for these specific models. In contrast, the sibling route `/api/Cards/:id` correctly enforces an ownership check, indicating that whatever access-control layer exists in this application is applied per-route/per-model rather than as a secure-by-default framework setting — meaning any new model added to the application is insecure by default unless a developer remembers to add the check explicitly.

## Remediation

1. **Apply role-based and ownership-based access control middleware as a secure default across all `/api/<Model>/` REST-scaffolded routes**, rather than adding it selectively per-model. Any new model should be protected automatically, not require a developer to remember to add a check.
2. **`GET /api/Users` should require an `admin` role at minimum**, and should never return the `deluxeToken` field to any requester other than the account owner or a genuine admin session — consider excluding sensitive fields from this endpoint's serialization entirely regardless of caller.
3. **`DELETE /api/Feedbacks/:id` should verify the requesting user's ID matches the feedback record's owning user** (or that the requester holds an `admin` role) before allowing deletion.
4. **Audit every other `/api/<Model>/` route** in the application (e.g., `Addresss`, `Products`, `BasketItems`, `Challenges`) for the same missing-middleware pattern, using `/api/Cards/:id`'s correct behavior as the reference implementation for what "protected" should look like.
5. Add automated regression tests asserting that a `customer`-role token cannot read `/api/Users` or delete another user's `/api/Feedbacks/:id` record, to prevent regression if middleware is added and later removed or bypassed.

## Related Findings

- **F-002** (JWT `alg:none` Account Takeover) — this finding originated as a direct follow-up test of F-002's forgery technique; ironically, it proved the technique was unnecessary on these two endpoints, since a genuine low-privilege token was already sufficient.
- **F-007** (Full User Database Extraction via SQL Injection) — both findings result in full user-table exposure; F-007 achieves it via SQL injection (no valid account needed at all), while this finding achieves a similar outcome via a completely legitimate, unprivileged session and no injection whatsoever — together they show the same sensitive data is reachable through two entirely independent, unrelated root causes.
- **F-005** (IDOR on Checkout) — same broad theme (missing ownership verification on user-supplied identifiers), different endpoint family; the `GET /api/Cards/:id` route tested during F-005-adjacent work is the correctly-protected counter-example that highlights how selectively this pattern has been applied across the codebase.

## Follow-Up Testing (planned)

- [ ] Systematically enumerate and test every other `/api/<Model>/` route for the same missing role/ownership check pattern (e.g., `Addresss`, `Products`, `BasketItems`).
- [ ] Determine whether `PUT`/`PATCH` operations on `/api/Users/:id` are similarly unprotected, once the unrelated JWT-decoding anomaly observed on that specific route during testing is isolated and understood (tracked separately — see `methodology-tracking-log.md`).
- [ ] Confirm whether `POST` (create) operations on `/api/Feedbacks/` or `/api/Users/` carry any authorization requirement, completing the CRUD coverage for this route family.

## References

- OWASP Top 10 2021 — A01: Broken Access Control
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
