# Finding F-001: Sensitive Data Exposure via JWT Payload

| Field | Value |
|---|---|
| Finding ID | F-001 |
| Title | Excessive/Sensitive Data Exposure in JWT Session Token |
| Category | OWASP Top 10 — A02:2021 Cryptographic Failures (also relates to A01 Broken Access Control in principle — sensitive fields should never reach the client) |
| Severity | High |
| Status | Confirmed |
| Affected Component | Session token issued at `/rest/user/login`, sent as `Authorization: Bearer <token>` on all subsequent requests (also observed as `token` cookie) |
| Date Identified | 2026-09-26 |

## Summary

The application issues a JSON Web Token (JWT) as the session credential after login.
Rather than containing only the minimal claims needed to identify a session (e.g., user
ID, expiry), the token's payload contains the user's **entire database record**,
including a password hash and a secondary sensitive token (`deluxeToken`). This data is
base64-encoded, not encrypted, meaning **anyone who intercepts or is handed this token
can trivially decode and read it** — no cracking or exploitation required, only decoding.

## Technical Detail

JWTs are signed (integrity-protected) but **not encrypted** by default. The payload
segment is simply base64url-encoded JSON, decodable by anyone using a public tool
(e.g., jwt.io) or a one-line script, without needing the signing key.

Decoded payload observed (values below are from a disposable test account created
solely for this assessment; no real user data is affected):

```json
{
  "status": "success",
  "data": {
    "id": 25,
    "username": "123",
    "email": "test@gmail.com",
    "password": "16d7a4fca7442dda3ad93c9a726597e4",
    "role": "deluxe",
    "deluxeToken": "ee12a92d0b09d7a738b9f40c6c36e0557ddd3ae6a8a52c7284291e78af12b4de",
    "lastLoginIp": "",
    "profileImage": "/assets/public/images/uploads/25.jpg",
    "totpSecret": "",
    "isActive": true,
    "createdAt": "2026-09-25T12:52:29.512Z",
    "updatedAt": "2026-09-25T15:32:21.067Z",
    "deletedAt": null
  },
  "iat": 1790350341
}
```

Header:
```json
{ "typ": "JWT", "alg": "RS256" }
```

## Issues Identified

1. **Password hash exposed client-side.** The `password` field is a 32-character hex
   string, consistent with an **unsalted MD5** hash — MD5 is cryptographically broken
   and unsuitable for password storage regardless of exposure. Shipping it to the
   client at all is a separate, compounding failure on top of the weak algorithm choice.
2. **`deluxeToken` exposed.** A second sensitive, credential-like value is present in
   every request the browser makes — increasing the value of a stolen token to an
   attacker and the blast radius of any token leak (e.g., via XSS, logging,
   browser history, proxy logs, referer leakage).
3. **No claim minimization.** Fields like `createdAt`, `updatedAt`, `deletedAt`,
   `isActive`, and `lastLoginIp` provide no functional value to the client and should
   never be embedded in a bearer token.
4. **No encryption layer (JWE).** Given the sensitivity of the embedded data, the
   application would need JWE (encrypted JWT), not just JWS (signed JWT), to safely
   carry this payload — or, correctly, should not carry this data in the token at all.

## Impact

- Any party who obtains a user's token — via a compromised network, browser
  extension, XSS (see related findings), misconfigured logging, or a shared/public
  computer — immediately gains the user's password hash and deluxe-membership
  token without needing to defeat the JWT's signature at all.
- If the hash is crackable (weak/common password, MD5 with no salt is fast to
  brute-force), this escalates directly to full account compromise, including on
  any other service where the user reused that password.
- Increases the value of any successful XSS finding elsewhere in the app, since
  token theft becomes significantly more damaging than a typical session-only token.

## Steps to Reproduce

1. Log in to the application as any user.
2. Intercept any authenticated request (e.g., `GET /rest/user/whoami`) with a
   proxy (Burp Suite).
3. Copy the value of the `Authorization: Bearer <token>` header.
4. Decode it using any public JWT decoder (e.g., jwt.io) or:
   `echo '<payload_segment>' | base64 -d` (no key required — decoding, not cracking).
5. Observe that the decoded payload contains password hash, deluxe token, and
   internal record metadata.

## Evidence

See `evidence/requests-responses/F-001-whoami-request.txt` (header names preserved;
signature segment truncated before committing) and
`evidence/screenshots/F-001-jwtio-decode.png` (jwt.io decode view).

*(Sanitization note: when saving evidence into the repo, truncate the token's
signature segment and consider partially masking the password-hash and
deluxeToken values, e.g. showing only the first/last 4 characters, since this
demonstrates the finding just as effectively without publishing full sensitive
strings on a public GitHub repo.)*

## Remediation

1. **Reduce JWT claims to the minimum necessary** — typically just a subject
   identifier (user ID) and standard claims (`iat`, `exp`, `nbf`). Look up any
   additional user data server-side on each request instead of embedding it.
2. **Never include password hashes, tokens, or secrets in a JWT payload**, encrypted
   or not — treat the token as public information the moment it leaves the server.
3. **Migrate password hashing off MD5** to a modern, slow, salted algorithm
   (bcrypt, scrypt, or Argon2).
4. If additional claims are genuinely required client-side, consider a JWE
   (encrypted JWT) rather than JWS-only, or keep the token opaque and let the
   server maintain session state.

## References

- OWASP Top 10 2021 — A02: Cryptographic Failures
- CWE-522: Insufficiently Protected Credentials (password hash transmitted to the client within the token)
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (deluxeToken and internal record metadata)
- OWASP JWT Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
