# Finding F-002: JWT Signature Verification Bypass Leading to Full Account Takeover

| Field | Value |
|---|---|
| Finding ID | F-002 |
| Title | Authentication Bypass via Unsigned JWT (`alg: none`) — Full Account Takeover |
| Category | OWASP Top 10 — A07:2021 Identification and Authentication Failures (root cause); results in A01:2021 Broken Access Control (impact) |
| Severity | **Critical** |
| CVSS 3.1 (estimated) | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Status | Confirmed, reproduced twice independently |
| Affected Component | JWT verification middleware on all authenticated `/rest/*` and `/api/*` endpoints |
| Date Identified | 2026-09-28 |

## Summary

The application issues JWTs signed with `RS256`, but **does not enforce or verify the
token's signature algorithm or signature value on incoming requests**. An attacker can
submit a token with the header changed to `{"alg":"none","typ":"JWT"}` and the
signature segment removed entirely, and the server will still accept the token as
valid — trusting whatever claims (user ID, email, role, basket ID) the attacker
chooses to write into the payload.

This was proven not just theoretically, but with a live, end-to-end demonstration:
a token was handcrafted from scratch, claiming to be a real second user account
(**User B**), including a fabricated password field never obtained from that user,
and the server returned that user's genuine private data (their shopping basket)
in response.

## Severity Justification

This is rated **Critical** rather than High because:
- No authentication step (password, session theft, MFA bypass) was required —
  the attacker only needs to know or guess a target's user ID.
- The attack requires no interaction from the victim.
- It grants full impersonation, not just read access to one field — any endpoint
  trusting this token would treat the attacker as that user.
- It was reproduced consistently across two different accounts.

## Steps to Reproduce

1. Log in as any user (User A) and capture a legitimate JWT via a proxy (Burp Suite).
2. Decode the token's payload (base64url, no key required).
3. Construct a new token:
   - Header: `{"alg":"none","typ":"JWT"}`, base64url-encoded.
   - Payload: the same structure, with `data.id` and `data.email` changed to a
     **different, real user's** ID and email (User B, `id: 27`,
     `email: testuser-b@example.local`), and `data.password` set to an arbitrary
     placeholder string.
   - Signature: omitted entirely (token ends in a trailing `.` with nothing after it).
4. Submit this forged token as both the `Authorization: Bearer <token>` header and
   the `token` cookie in a request to `GET /rest/basket/8` (User B's basket, `bid`
   value taken from the forged payload).
5. Observe the server returns **HTTP 200** with User B's real basket record.

## Evidence

**Forged, unsigned JWT payload used (decoded for readability):**
```json
{
  "data": {
    "id": 27,
    "email": "testuser-b@example.local",
    "password": "forged-does-not-matter",
    "role": "customer"
  },
  "bid": 8
}
```
Header: `{"alg":"none","typ":"JWT"}` — no signature segment present.

**Server response (`GET /rest/basket/8`):**
```
HTTP/1.1 200 OK
...
{"status":"success","data":{"id":8,"coupon":null,"UserId":27,"createdAt":"2026-09-28T16:00:24.300Z","updatedAt":"2026-09-28T16:00:24.300Z","Products":[]}}
```

`UserId: 27` and basket `id: 8` match User B's real account exactly — confirmed by
cross-referencing against User B's own legitimate session captured minutes earlier
(see `F-001` evidence and `evidence/requests-responses/F-002-*`), in which the real
`RS256`-signed token also contained `"bid":8`.

Full raw requests/responses are stored in
`evidence/requests-responses/F-002-forged-token-basket-access.txt`
(both the legitimate User B baseline capture and the forged-token exploitation
request are included, for direct comparison).

*(Sanitization note: forged tokens in evidence contain only synthetic test data —
no real credentials — but should still be clearly labeled as "forged/attacker-
controlled" in any evidence file so a reader doesn't mistake them for legitimately
issued tokens.)*

## Impact

If this were a production application:
- Any authenticated or even unauthenticated attacker who can guess or enumerate a
  numeric user ID could **read, and — pending further testing — likely modify**
  any user's account data, basket, orders, and payment information.
- Combined with **F-001** (password hashes embedded in JWTs), an attacker doesn't
  even need to forge a token from scratch — they could take any legitimately
  intercepted token, strip its signature, and freely edit the role or user ID.
- Role escalation is trivially possible: the same technique with `"role":"admin"`
  in the forged payload should be tested against admin-only endpoints next
  (planned as a follow-up test) to determine if administrative functions are
  reachable the same way.
- This single flaw effectively negates the value of the entire authentication
  system — password strength, MFA (`totpSecret` field present in the schema),
  and account lockout policies all become irrelevant once tokens aren't verified.

## Root Cause

The server-side JWT verification logic is not enforcing the signing algorithm and/or
is not validating the signature before trusting the token's claims. Common causes
of this exact bug class include:
- Using a JWT library in a mode that allows `alg: none` unless explicitly disabled.
- Decoding the token (reading claims) without ever calling a *verify* function.
- Accepting the client-supplied `alg` header value rather than pinning the
  algorithm server-side.

## Remediation

1. **Explicitly reject `alg: none`** at the JWT library/middleware level — most
   modern JWT libraries require this to be disabled explicitly; confirm it is.
2. **Pin the expected algorithm server-side** (e.g., always verify as `RS256`)
   rather than trusting the `alg` field from the token header at all.
3. **Always call the library's verify function**, not just decode, on every
   authenticated request — verification must check both signature and algorithm.
4. Add automated regression tests that specifically submit `alg: none` and
   mismatched-algorithm tokens and assert a 401 response.
5. Re-issue all existing sessions after the fix ships, since any previously
   issued token's claims can no longer be trusted to represent legitimate intent.

## Related Findings

- **F-001** (Sensitive Data Exposure via JWT Payload) — compounds this issue,
  since the password hash and deluxe token are also exposed and could be lifted
  from any intercepted token.

## Follow-Up Testing (planned)

- [ ] Test the same technique with `"role":"admin"` against
      `/rest/admin/application-configuration` and other admin-only endpoints
      identified in the attack surface map, to determine the full extent of
      privilege escalation possible.
- [ ] Test whether write operations (e.g., `PUT`/`POST` to profile, basket,
      checkout) also trust forged tokens, not just `GET` reads.

## References

- OWASP Top 10 2021 — A07: Identification and Authentication Failures
- CWE-347: Improper Verification of Cryptographic Signature
- OWASP JWT Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
