# Finding F-011: Verbose Database Error Disclosure on Cards and Complaints Endpoints

| Field | Value |
|---|---|
| Finding ID | F-011 |
| Title | Raw SQLite Constraint Errors Exposed to Client on `/api/Cards/` and `/api/Complaints/` |
| Category | OWASP Top 10 — A05:2021 Security Misconfiguration |
| Severity | Low |
| Status | Confirmed |
| Affected Component | `POST /api/Cards/`, `POST /api/Complaints/` |
| Date Identified | 2026-09-29 |

## Summary

Submitting a request to either `POST /api/Cards/` or `POST /api/Complaints/` with an incomplete or malformed body causes both endpoints to fail with an unhandled `500 Internal Server Error`, and both return the **raw underlying database error message** directly in the JSON response body — including the exact SQLite constraint that failed. This was reproduced independently on two separate endpoints and across two different user sessions, confirming it is a consistent, systemic pattern rather than an isolated glitch.

While this does not directly grant unauthorized access to data, it confirms the backend database engine (SQLite) and leaks internal schema relationship details (foreign key dependencies) that should never be surfaced to a client — information that lowers the effort required for further, more targeted attacks.

## Steps to Reproduce

**On `/api/Cards/`:**
1. Log in as any user.
2. Send `POST /api/Cards/` with a body missing a required related-record reference (e.g., omitting or providing an invalid linkage the schema expects):
   ```json
   {"fullName":"123123","cardNum":1231231231231232,"expMonth":"1","expYear":"2081"}
   ```
3. Observe `HTTP 500` with the raw database error in the response body.

**On `/api/Complaints/`:**
1. Log in as any user.
2. Send `POST /api/Complaints/` with a body missing the file-attachment reference the schema expects:
   ```json
   {"UserId":25,"message":"1111111"}
   ```
3. Observe the identical failure pattern — `HTTP 500` with the same class of raw database error.

## Evidence

**`POST /api/Cards/` — reproduced twice, on two separate accounts:**

Attempt 1 (User B, `testuser-b@example.local`):
```
POST /api/Cards/ HTTP/1.1
Content-Type: application/json

{"fullName":"123123","cardNum":1231231231231232,"expMonth":"1","expYear":"2081"}

HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8

{"message":"internal error","errors":["SQLITE_CONSTRAINT: FOREIGN KEY constraint failed"]}
```

Attempt 2 (separate session, same account, same payload) — identical result, confirming reproducibility rather than a one-off race condition.

**`POST /api/Complaints/` (User A, `test@gmail.com`):**
```
POST /api/Complaints/ HTTP/1.1
Content-Type: application/json

{"UserId":25,"message":"1111111"}

HTTP/1.1 500 Internal Server Error
Content-Type: application/json; charset=utf-8

{"message":"internal error","errors":["SQLITE_CONSTRAINT: FOREIGN KEY constraint failed"]}
```

Both endpoints return the exact same underlying error string format, strongly suggesting both are backed by the same ORM/database layer failing in the same way — most likely both records require an associated `File` (attachment) reference at the database level that the client-supplied request did not satisfy, and the resulting constraint violation is passed straight through to the HTTP response unhandled.

Full raw requests/responses saved in
`evidence/requests-responses/F-011-verbose-sql-errors.txt`.

## Impact

- **Confirms the backend database engine (SQLite)** to any client capable of triggering a malformed request — useful reconnaissance for an attacker refining further injection attempts (consistent with what was already independently confirmed via the verbose error messages that assisted **F-007**'s exploitation).
- **Leaks internal schema relationships** (specifically, that `Cards` and `Complaints` records have a `FOREIGN KEY` dependency on another table, almost certainly a `Files`/attachment table) that have no business being visible to a client under any circumstance.
- **Confirms the application does not have centralized, generic error handling** for unexpected database failures — raw driver/ORM exceptions are propagating all the way to the HTTP response layer unmodified. This is the same class of oversight, at the error-handling layer, that made **F-007**'s SQL injection materially easier to discover and exploit in the first place (verbose errors revealed exact query structure and column counts).
- **Low severity** because this specific instance does not leak user data, credentials, or allow any direct exploitation on its own — it is an information-disclosure and defense-in-depth gap, not a standalone high-impact vulnerability.

## Root Cause

Neither endpoint appears to have server-side input validation to confirm the request body is complete and well-formed *before* attempting a database write, and neither has a generic error-handling middleware that catches unhandled database exceptions and returns a sanitized, generic error message instead of the raw driver output. The `500` responses show the ORM/database layer's native error object being serialized directly into the HTTP response.

## Remediation

1. **Validate request bodies against an expected schema before attempting any database operation**, rejecting incomplete/malformed requests with a clean `400 Bad Request` and a generic, non-technical error message — never reaching the point where a database constraint violation can occur from malformed client input in the first place.
2. **Add centralized error-handling middleware** that catches all unhandled exceptions (database or otherwise) application-wide and returns a sanitized, generic `500` response (e.g., `{"message":"An unexpected error occurred"}`) with no internal error details, regardless of which endpoint or code path failed.
3. **Log full error details server-side only** (for debugging/monitoring), never in the client-facing response.
4. **Audit other endpoints for the same pattern** — given this was confirmed on two independent routes, other write endpoints (e.g., `Addresss`, `Feedbacks`) are worth a quick check for the same unhandled-exception behavior.

## Related Findings

- **F-007** (Full User Database Extraction via SQL Injection) — established the broader pattern that this application's verbose/unhandled database errors materially assist exploitation; this finding shows the same unhandled-error pattern exists on additional, unrelated endpoints beyond the ones directly exploited in F-007.
- **F-010** (Missing/Inconsistent Security Headers) — both findings fall under the same OWASP category (A05: Security Misconfiguration) and reflect a similar theme: individually low-severity gaps in defense-in-depth and error/response hygiene across the application, rather than a single high-impact bug.

## References

- OWASP Top 10 2021 — A05: Security Misconfiguration
- CWE-209: Generation of Error Message Containing Sensitive Information
