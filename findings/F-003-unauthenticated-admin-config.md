# Finding F-003: Missing Authentication on Admin Configuration Endpoint

| Field | Value |
|---|---|
| Finding ID | F-003 |
| Title | Unauthenticated Access to `/rest/admin/application-configuration` |
| Category | OWASP Top 10 — A01:2021 Broken Access Control |
| Severity | High |
| Status | Confirmed |
| Affected Component | `GET /rest/admin/application-configuration` |
| Date Identified | 2026-09-28 |

## Summary

The endpoint `/rest/admin/application-configuration` — named and path-scoped as an
**admin** resource — returns a complete dump of the application's internal
configuration to **any request, including one with no authentication credentials
whatsoever** (no `Authorization` header, no session cookie). This was proven
independently of the JWT signature bypass documented in F-002: even with every
authentication-related header stripped from the request entirely, the endpoint
still returns HTTP 200 with full data.

## Steps to Reproduce

1. Send the following request with no prior login, no cookies, and no
   `Authorization` header:
   ```
   GET /rest/admin/application-configuration HTTP/1.1
   Host: localhost:3000
   Accept: application/json, text/plain, */*
   Connection: keep-alive
   ```
2. Observe the response: `HTTP/1.1 200 OK` with a large JSON body under a `config`
   key.

## Evidence

Request sent (headers only, no cookies, no Authorization):
```
GET /rest/admin/application-configuration
Host: localhost:3000
Accept: application/json, text/plain, */*
Connection: keep-alive
```

Response (truncated for this summary — full body saved in evidence folder):
```
HTTP/1.1 200 OK
...
{"config":{"server":{"port":3000,...},"application":{"domain":"juice-sh.op",
"name":"OWASP Juice Shop",...,"googleOauth":{"clientId":"1005568560502-...
.apps.googleusercontent.com","authorizedRedirects":[...]}},...}}
```

Full response saved in `evidence/requests-responses/F-003-unauthenticated-admin-config.txt`.

## Data Exposed

The response discloses, among other things:
- Full application/server configuration structure
- **Google OAuth `clientId`** and the complete list of `authorizedRedirects` URIs
  (useful reconnaissance for an attacker targeting OAuth flows or attempting
  redirect URI manipulation)
- Internal challenge/CTF configuration flags (`codingChallengesEnabled`,
  `restrictToTutorialsFirst`, hint/mitigation display settings)
- A CSAF security advisory hash value
- Security contact and PGP key fingerprint information
- Full product catalog data (lower sensitivity, but confirms the endpoint is a
  broad, unfiltered internal-config dump rather than a narrow, intended-public
  settings endpoint)

None of this rises to the level of credentials or PII, which is why this is scored
**High** rather than Critical — but it is a clear, real broken-access-control bug:
a path explicitly named `/admin/` should never be reachable without authentication,
regardless of what it happens to expose today. The OAuth client configuration in
particular could assist an attacker chaining this with other issues.

## Impact

- Confirms a broader pattern: authentication checks on this application cannot be
  assumed to exist even on endpoints whose naming strongly implies restriction.
- Provides free reconnaissance data to any anonymous visitor, reducing the effort
  needed for further attacks (e.g., knowing the exact OAuth client ID and redirect
  URIs in advance).
- Independent of F-002 — even a complete fix to the JWT signature verification bug
  would **not** resolve this finding, since no token is checked here at all. This
  needs to be fixed as its own issue.

## Root Cause

The route handler for this endpoint appears to have no authentication middleware
applied at all, as opposed to F-002's issue of authentication middleware being
present but not correctly verifying signatures.

## Remediation

1. Add authentication middleware to this route requiring a valid, signature-verified
   session (which also depends on fixing F-002 first).
2. Add authorization/role-checking middleware requiring an `admin` role specifically
   — being logged in as any customer should not be sufficient either.
3. Review all other `/rest/admin/*` and `/api/admin/*` style routes for the same
   missing-authentication pattern (e.g., `/rest/admin/application-version`, seen
   during recon, should be checked too).
4. Consider whether this configuration data needs to be exposed via any endpoint
   at all, versus being split into a genuinely public subset (e.g., theme/branding)
   and a genuinely internal subset (OAuth config, CSAF hash) served separately
   with real access control.

## Related Findings

- **F-002** — the JWT signature bypass; this finding shows the problem is broader
  than just signature verification, since this endpoint bypasses authentication
  entirely rather than accepting a forged token.

## References

- OWASP Top 10 2021 — A01: Broken Access Control
- CWE-306: Missing Authentication for Critical Function
