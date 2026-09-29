# Finding F-008: Missing Type Validation Allows MongoDB Operator Objects to Be Stored as Review Content

| Field | Value |
|---|---|
| Finding ID | F-008 |
| Title | NoSQL Operator/Type Confusion via Unvalidated `message` Field in Review Submission |
| Category | OWASP Top 10 — A03:2021 Injection (NoSQL) / A04:2021 Insecure Design |
| Severity | Low |
| Status | Confirmed |
| Affected Component | `PUT /rest/products/:productId/reviews` — `message` field |
| Date Identified | 2026-09-29 |

## Summary

The review submission endpoint does not enforce that the `message` field must be a
plain string. Submitting a JSON object shaped like a MongoDB query operator (e.g.
`{"$gt": ""}`) in place of a normal string is accepted (`201 Created`) and persisted
to the database without validation or rejection. The malformed value is later
rendered to **every visitor** viewing that product's reviews as the literal text
`[object Object]`, since the frontend naively stringifies whatever value it receives
rather than expecting only strings.

This is scored **Low** rather than Critical/High because, in the specific case
tested, the malformed input was only ever used for storage and display — it was
not evaluated in a query context where a MongoDB operator would change query
*logic* (unlike F-007, where injected content directly altered a SQL query's
behavior). The significance here is the confirmed **absence of input type
validation**, which is a root-cause pattern worth flagging even where this
particular instance's impact is limited to cosmetic data corruption.

## Steps to Reproduce

1. Log in as any user.
2. Submit `PUT /rest/products/1/reviews` with the following body:
   ```json
   {"message": {"$gt": ""}, "author": "nosqli-operator-test"}
   ```
3. Observe `201 Created`, `{"status":"success"}` — the request is accepted with
   no validation error, despite `message` not being a string.
4. View the product's reviews (`GET /rest/products/1/reviews` or the product
   page in the UI). Observe the new review displays as literal text
   `[object Object]` instead of any readable content, for **any user who
   views the page**, not just the submitter.

## Evidence

**Request:**
```
PUT /rest/products/1/reviews HTTP/1.1
Content-Type: application/json

{"message": {"$gt": ""}, "author": "nosqli-operator-test"}
```

**Response:**
```
HTTP/1.1 201 Created
{"status":"success"}
```

**Resulting stored/rendered review**, visible on the product page reviews list
alongside legitimate reviews:
```
nosqli-operator-test
[object Object]
```

Full raw request/response saved in
`evidence/requests-responses/F-008-nosql-type-confusion.txt`.

## Impact

- **Confirmed absence of server-side schema/type validation** on the `message`
  field — any JSON value type (object, array, number, boolean) is likely
  accepted where only a string should be, not just the specific operator-shaped
  payload tested.
- **Persistent, visible data corruption**: the malformed review is stored
  permanently and degrades the product page for every visitor until manually
  cleaned up — a low-grade but real availability/data-integrity issue.
- **Elevated risk if reused elsewhere**: this same missing-validation pattern,
  if present on any field that *is* later used inside a MongoDB query filter
  (rather than only stored/displayed, as tested here), would allow genuine
  NoSQL query-logic injection — comparable in severity to F-007's SQL
  equivalent. This endpoint specifically was not shown to have that deeper
  impact, but the missing validation itself is the same class of root cause,
  and other fields/endpoints should be checked (see Follow-Up Testing).
- Reinforces the input-validation gap already identified in **F-004** (which
  found the same endpoint accepts unexpected fields like `id`/`_id` without
  rejection) — this is now the second distinct validation failure found on
  this single endpoint, suggesting the review-creation handler in particular
  has no meaningful request-body schema enforcement at all.

## Root Cause

The review-creation handler does not validate incoming field types against an
expected schema before persisting to MongoDB (via Mongoose or equivalent ODM).
Without an explicit schema type constraint (e.g., `message: { type: String,
required: true }` enforced strictly), MongoDB/Mongoose can silently accept and
store arbitrary JSON shapes.

## Remediation

1. **Enforce strict schema typing** on the `Review` model — `message` and
   `author` must be validated as strings (with reasonable length limits) before
   any database write, rejecting the request with a `400` if the type does not
   match.
2. **Apply this validation consistently** across all user-content fields in the
   application, not just this endpoint — combine with the recommendation
   already made in F-004 to whitelist and type-check the entire request body
   schema.
3. **Sanitize/validate on the frontend as well** as a defense-in-depth measure
   (though server-side validation remains the authoritative control) — the
   `[object Object]` rendering bug itself is a symptom of the frontend also
   trusting the API response shape without checking it.
4. As part of the broader NoSQL-injection review recommended in Follow-Up
   Testing, specifically audit any endpoint where user input is used inside a
   MongoDB **query filter** (not just stored) for the same missing-validation
   pattern, since that is where this bug class becomes genuinely dangerous.

## Related Findings

- **F-004** (Review Author Field Client-Controlled) — same endpoint, same
  underlying root cause (no request-body schema validation); this finding adds
  a second, independently-confirmed validation gap on the identical handler.
- **F-007** (SQL Injection — Full Database Extraction) — the SQL-side
  equivalent of "unvalidated input reaching a query engine's logic layer";
  this finding shows the same class of risk exists on the NoSQL side of the
  application's mixed-database architecture, even though this specific
  instance's impact was limited to storage/display rather than query-logic
  manipulation.

## Follow-Up Testing (planned)

- [ ] Test other MongoDB-backed endpoints (e.g., `/api/Feedbacks/`) for the
      same operator-object acceptance.
- [ ] Specifically test any endpoint where user input is used to **filter or
      search** MongoDB-backed data (not just create/store it) — this is where
      operator injection would achieve F-007-level impact rather than only
      cosmetic corruption.
- [ ] Test additional MongoDB operators beyond `$gt` (e.g., `$where`, `$regex`,
      `$ne`) for different behaviors, particularly `$where`, which can execute
      arbitrary JavaScript server-side in vulnerable MongoDB configurations.

## References

- OWASP Top 10 2021 — A03: Injection
- CWE-20: Improper Input Validation
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
  (NoSQL Injection)
