# Finding F-004: Unauthenticated/Unattributed Review Injection via Malformed Review Body

| Field | Value |
|---|---|
| Finding ID | F-004 |
| Title | Review Creation Endpoint Accepts Unvalidated `id` Field, Producing Orphaned Reviews With No Author |
| Category | OWASP Top 10 — A04:2021 Insecure Design (input validation gap) / A08:2021 Software and Data Integrity Failures |
| Severity | Low–Medium |
| Status | Confirmed |
| Affected Component | `PUT /rest/products/:productId/reviews` |
| Date Identified | 2026-09-29 |

## Summary

This finding started as an attempt to prove a horizontal-access-control bug: that
one user could edit another user's existing review (a classic IDOR pattern). That
specific hypothesis was **tested and disproven** — see "Investigation Notes"
below for the full methodology, since the negative result is itself useful
evidence of what the endpoint does *not* do.

What was proven instead: `PUT /rest/products/:productId/reviews` is a
**create-only** endpoint in this version, and it will happily create a new
review when the request body contains an unrecognized `id` (or `_id`) field —
producing a permanently stored review with **no `author` field at all**,
regardless of which user's session sent the request.

## Investigation Notes (methodology and disproven hypothesis)

To test for edit-based IDOR, the following was attempted, in order:
1. `PUT` with body `{"id": "<existing review's _id>", "message": "..."}`,
   authenticated as a *different* user than the review's original author.
2. Same, using `PATCH` instead of `PUT` (the app's own challenge-tracker
   flagged the first `PUT` attempt as solving a "Forged Review" challenge,
   suggesting a written edit *might* be expected via some method).
3. Same as (1), but with the key renamed to `_id` (MongoDB's actual internal
   field name) rather than `id`.

**Result in every case:** the targeted review (`_id: nXjZjMrjRd8XtoHkB`,
`message: "123456"`, `author: testuser-a@example.local`) was **never modified**
across repeated verification via `GET /rest/products/1/reviews`. `PATCH`
returned `500 Internal Server Error` ("Unexpected path") — confirming no route
is registered for that method at all. Both `PUT` attempts with an `id`/`_id`
field instead created **new, separate review documents**, each missing the
`author` field.

This negative result matters: the app's own "Forged Review" challenge
completion should **not** be taken as proof that an edit occurred — it appears
to fire on a looser pattern match (e.g., "a PUT to this route occurred while
authenticated as a user other than a review's original author") rather than
verifying an actual state change. Always confirm against real data, not the
application's self-reported challenge status.

## Steps to Reproduce (the confirmed bug)

1. Log in as any user.
2. Send `PUT /rest/products/1/reviews` with a body containing an `id` (or
   `_id`) field that does not correspond to a real, existing review:
   ```json
   {"id":"nXjZjMrjRd8XtoHkB","message":"EDITED-BY-USER-B-IDOR-TEST"}
   ```
   (Note: in this example the ID *does* correspond to a real review belonging
   to a different user — but the server does not use it to locate or update
   that review; it is simply ignored for lookup purposes.)
3. Observe `201 Created`, `{"status":"success"}`.
4. `GET /rest/products/1/reviews` and observe a new review entry has been
   added, containing the submitted `message`, but with **no `author` field
   present at all** — unlike every legitimately-created review, which always
   has one.
5. Repeat with `_id` instead of `id` as the key — same result.

## Evidence

**Two orphaned reviews produced during testing, both missing `author`:**
```json
{"product":"1","message":"EDITED-BY-USER-B-IDOR-TEST","likesCount":0,"likedBy":[],"_id":"KXCktrQQNRHjX87yx"}
{"product":"1","message":"EDITED-BY-USER-B-REAL-TEST","likesCount":0,"likedBy":[],"_id":"tBH6E9gs3dEPE6HSc"}
```

**Compare to a normal, legitimately-created review (has `author`):**
```json
{"product":"1","message":"1234","author":"testuser-b@example.local","likesCount":0,"likedBy":[],"_id":"m6knT3FAYbcbmrMow"}
```

**Target review, confirmed unchanged throughout all attempts:**
```json
{"product":"1","message":"123456","author":"testuser-a@example.local","likesCount":0,"likedBy":[],"_id":"nXjZjMrjRd8XtoHkB"}
```

Full raw requests/responses saved in
`evidence/requests-responses/F-004-review-injection.txt`.

## Impact

- Any authenticated user can create reviews on any product with **no author
  attribution**, which could be used to post spam, misleading claims, or
  defamatory content that cannot be traced back to an account in the review
  data itself — undermining the integrity/trust signal reviews are meant to
  provide.
- The endpoint's silent acceptance of an unrecognized `id` field (rather than
  rejecting the request, or actually using it to look up a target record)
  indicates a broader **input validation gap**: extra, unexpected fields in
  the request body are not rejected, which is a code smell worth flagging even
  beyond this specific symptom — it suggests the underlying data model/ORM
  layer may accept partially-formed documents elsewhere too.
- Lower severity than originally hypothesized: this does **not** allow
  modifying another user's existing data, only creating new, improperly-formed
  data. Rated Low–Medium rather than the High/Critical tier of F-002/F-005.

## Root Cause

The review-creation handler does not validate the incoming request body against
an expected schema (rejecting unknown fields such as `id`), and does not
enforce that `author` is present/derived from the authenticated session before
persisting the document — consistent with a loosely-typed NoSQL insert that
accepts whatever shape of object it is given.

## Remediation

1. Explicitly validate and whitelist the fields accepted in the review-creation
   request body; reject requests containing unrecognized fields (e.g., `id`)
   rather than silently accepting them.
2. Always derive `author` server-side from the authenticated session — never
   allow it to be absent, and never trust a client-supplied value for it
   either (see also the client-supplied `author` field observed in normal
   review creation, which is a separate, related hardening opportunity: the
   server currently trusts whatever `author` string the client sends, rather
   than deriving it from the session token).
3. If an edit capability is intended to exist for reviews, implement and
   document it explicitly (with a real ownership check), rather than leaving
   the create endpoint to silently mishandle edit-shaped requests.

## Related Findings

- **F-005** (IDOR on Checkout) — the same general project phase (Step 5,
  authorization testing) produced a confirmed, higher-severity IDOR; this
  finding shows the value of testing a hypothesis rigorously even when it
  turns out to disprove the original theory, since a real (if smaller) bug was
  still found in the process.

## References

- OWASP Top 10 2021 — A04: Insecure Design
- CWE-20: Improper Input Validation
