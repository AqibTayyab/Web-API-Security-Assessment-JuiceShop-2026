# Finding F-004: Unauthenticated/Unattributed Review Injection via Malformed Review Body

| Field | Value |
|---|---|
| Finding ID | F-004 |
| Title | Review Author Field Is Fully Client-Controlled (Identity Spoofing), Plus Orphaned/Unattributed Reviews via Unvalidated `id` Field |
| Category | OWASP Top 10 — A04:2021 Insecure Design (missing server-side identity enforcement) / A08:2021 Software and Data Integrity Failures |
| Severity | Medium |
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

## Sub-Finding: Author Field Is Fully Client-Controlled (Confirmed, Not Hypothetical)

The related concern flagged in the original Remediation section — whether the
server trusts a client-supplied `author` value at all, even on ordinary review
creation — was tested directly and **confirmed**:

**Request** (authenticated as User A, `testuser-a@example.local`):
```json
PUT /rest/products/1/reviews
Authorization: Bearer <User A's real, valid token>

{"message":"Spoof-author-test","author":"totally-fake-person@example.local"}
```

**Result** — `201 Created`, and the review is persisted with the **spoofed**
author, not the authenticated user's real identity:
```json
{"product":"1","message":"Spoof-author-test","author":"totally-fake-person@example.local","likesCount":0,"likedBy":[],"_id":"Ri8vS2m5Ry7oTDbuM"}
```

No cross-check against the session's actual email was performed at any point.
This means **any logged-in user can publish a review that publicly displays as
having been written by any arbitrary name or email address** — including a
real third party's identity, a competitor, or a fabricated persona — entirely
independent of the orphaned-review/`id`-field bug documented above. This is
the more directly exploitable half of this finding: it requires no malformed
`id` field, no edge-case body — just a normal review submission with one
field's value changed.

## Impact

- **Confirmed identity spoofing**: any authenticated user can make a review
  appear to have been written by anyone else — a real customer, a company
  representative, or a fabricated identity — with no verification against the
  actual session. This is a direct impersonation/reputational-harm vector,
  independent of the orphaned-review issue.
- Any authenticated user can also create reviews on any product with **no
  author attribution at all** (the orphaned-review path), which could be used
  to post spam, misleading claims, or defamatory content that cannot be traced
  back to any account in the review data itself.
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

1. **Always derive `author` server-side from the authenticated session's
   verified email/identity** — never accept or trust a client-supplied
   `author` value under any circumstances. This is the primary fix; it
   resolves both the spoofing sub-finding and ensures the orphaned-review case
   can no longer produce an unattributed record either.
2. Explicitly validate and whitelist the fields accepted in the review-creation
   request body; reject requests containing unrecognized fields (e.g., `id`)
   rather than silently accepting them.
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
