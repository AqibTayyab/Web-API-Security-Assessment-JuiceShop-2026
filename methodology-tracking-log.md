# Methodology & Testing Log — Single Source of Truth

> Purpose: this document is the authoritative record of what has actually been
> tested, confirmed, or left open across this assessment. When in doubt about
> project status, this file — not memory of prior conversation — is the
> reference to trust. Update it every time a test is run or a finding is
> written, before moving to the next task.

Last updated: 2026-09-29 (Session covering F-006 through in-progress Phase 7 testing)

---

## 1. Written, Committed Findings (Confirmed, Documented, Pushed)

| ID | Title | Severity | Status |
|---|---|---|---|
| F-001 | Sensitive Data Exposure via JWT Payload | High | ✅ Written, committed |
| F-002 | JWT `alg:none` Signature Bypass — Account Takeover | Critical | ✅ Written, committed |
| F-003 | Unauthenticated Access to Admin Configuration Endpoint | High | ✅ Written, committed |
| F-004 | Review Author Field Spoofable + Orphaned Reviews | Medium | ✅ Written, committed |
| F-005 | IDOR on Checkout — Unauthorized Basket Checkout | Critical | ✅ Written, committed |
| F-006 | SQL Injection — Admin Login Bypass | Critical | ✅ Written, committed |
| F-007 | SQL Injection — Full User Database Extraction | Critical | ✅ Written, committed |
| F-008 | NoSQL Operator/Type Confusion in Reviews | Low | ✅ Written, committed |
| F-009 | DOM-Based XSS via Search Query Parameter (+ confirmed missing CSP) | High | ✅ Written, committed |
| F-010 | Missing/Inconsistent Security Headers (CSP, Feature-Policy, HSTS) | Low | ✅ Written — **confirm committed** |
| F-011 | Verbose SQL Error Disclosure (`/api/Cards/`, `/api/Complaints/`) | Low | ✅ Written — **confirm committed** |

**Action needed:** verify F-010 and F-011 were actually `git push`ed (last explicit confirmation in this log was for F-009 only). Run `git log --oneline -- findings/` to check both files are present in history before treating them as "done."

---

## 2. Negative Results (Tested, Confirmed NOT Exploitable — Documented as Notes Within Other Findings, Not Standalone)

These are real, useful results but were folded into related findings rather than given their own ID:

| Test | Result | Documented in |
|---|---|---|
| Stored XSS via review `message` field (`<script>` payload) | Rendered as escaped, inert text — not exploitable | F-009 (negative control) |
| SSRF via `/profile/image/url` (internal admin-config URL as `imageUrl`) | `profileImage` value unchanged after submission — no evidence of server-side fetch | Not yet written into any finding — **still needs a home**, see Section 4 |
| Basket **read** IDOR (`GET /rest/basket/8`, User A's token) | Returned `null` — read is protected, unlike checkout | F-005 (related testing note) — **confirm this note was actually added to the file; may still be pending** |
| Cross-user card read (`GET /api/Cards/8`, User B's token) | `400 "Malicious activity detected"` — protected | Not yet written into any finding — **still needs a home** |
| NoSQL `$where` operator in reviews | Stored inertly, same as `$gt` — no RCE on this endpoint | F-008 |
| Track-order accessed with **zero authentication** | Returned order data with no `Authorization`/`Cookie` at all | Confirmed, **not yet written anywhere** — likely intentional by-design (standard "track my order" UX pattern), not a bug on its own unless codes are guessable (untested, see Section 4) |

---

## 3. Phase 7 — Privilege Escalation Testing (IN PROGRESS — results so far are mixed/inconclusive, none written up yet)

**Original goal:** determine whether a forged `alg:none` JWT with `"role":"admin"` injected can bypass role-based access control anywhere in the app (following directly from the F-002 technique).

**What actually happened, in order:**

1. **`GET /api/Users`** — tested with both a real, unmodified customer token AND the forged admin-role token. **Both succeeded identically**, returning the full user table (all emails, roles, deluxe tokens). **Conclusion: this endpoint has no role check at all.** The forged token contributed nothing — a genuine customer token alone was sufficient. This is a real finding, but about **missing access control**, not about JWT forgery specifically.

2. **`DELETE /api/Feedbacks/1`** — tested with the real customer token first (meant as a "baseline expected to fail"). **It succeeded** (`200 OK`, record deleted) — no forgery needed. The subsequent forged-token request returned `404` only because the record was already gone from step 1's success, not because the forged token was rejected. **Conclusion: this endpoint also has no role/ownership check.** Second real finding of the same root-cause type.

3. **`PUT /api/Users/25`** (attempting self-role-escalation via a normal `PUT`) — tested with the real customer token. Result: `401 Unauthorized`, but with error `DECODER routines::unsupported` — an **OpenSSL key-parsing failure**, not a clean authorization rejection. This suggests either a broken/different JWT verification path specific to this one route, or a possible algorithm-confusion issue. **This result is NOT interpretable as evidence of role protection working** — it needs isolated follow-up before any conclusion is drawn. The forged-token version of this test was never sent, since the baseline itself didn't produce a clean, interpretable result.

**Current state:** two real findings identified (items 1 and 2 above) but not yet written up. Item 3 is an open anomaly, not yet understood, not yet retested cleanly.

**Decision made in-session, not yet executed:** write items 1 and 2 as a single combined finding (proposed ID: **F-012**, "Missing Role-Based Access Control on REST-Scaffolded Endpoints") since they share the same root cause — Sequelize's auto-generated REST routes (`/api/Users`, `/api/Feedbacks`, likely others) appear to have no role or ownership middleware applied at all, in contrast to the hand-written `/rest/*` routes which do enforce some checks (e.g., F-005's basket-read protection, the `/api/Cards/8` "Malicious activity detected" block).

**This finding has NOT been written yet as of this log's last update.**

---

## 4. Confirmed But Homeless (tested, real result, not yet written into any finding file)

| Item | Result | Recommended home |
|---|---|---|
| SSRF probe via `/profile/image/url` | Negative — no evidence of server-side fetch | New short finding, or a "Follow-Up Testing" note if scored not worth a full write-up |
| `GET /api/Cards/8` cross-user block | Positive control — access denied correctly | Should be added as a note to F-005 (contrasts with checkout's lack of protection) |
| Basket read IDOR protection | Positive control — access denied correctly | Should be added as a note to F-005 |
| Track-order with zero auth | By-design, not yet a finding | Needs 2-3 more tracking codes compared for predictability before deciding if it's F-0XX (enumeration) or just a summary note |
| `PUT /api/Users/25` OpenSSL decoder error | Anomaly, uninterpreted | Needs isolated retesting — is this route-specific, or does the same error occur on other `PUT`/`PATCH` admin-shaped routes? |
| Stack trace disclosure on `/api/Users/25` 401 error (`Express ^4.22.1` + internal error class name) | Confirmed | Should be added as a one-line note to F-011 (same error-disclosure theme, different layer — middleware vs. database) |

---

## 5. Not Yet Started (Phase 7 remaining + Phase 8 backlog)

- [ ] `paymentId`/`addressId` ownership validation at checkout (flagged in F-005's own follow-up)
- [ ] Isolate and explain the `PUT /api/Users/25` OpenSSL decoder anomaly
- [ ] Track-order code enumeration/predictability (need 3-4 codes compared side by side)
- [ ] Decide fate of the "confirmed but homeless" items in Section 4

---

## 6. Housekeeping Debt (not testing — paperwork)

- [ ] Confirm F-010 and F-011 are actually committed and pushed to GitHub (not just downloaded locally)
- [ ] Regenerate `summary.md` once all of the above is finalized — **intentionally deferred until the end, per project decision**
- [ ] Add the F-005 positive-control notes (basket read, card read) into F-005's file
- [ ] Add the stack-trace disclosure note into F-011's file
- [ ] Decide and write up F-012 (missing RBAC on REST-scaffolded endpoints) from Section 3, items 1–2

---

## How to use this file going forward

Before starting any new test, check Sections 3–5 first — they represent the actual
current frontier of the project. Before writing any new finding, check Section 1
to confirm the next available ID and avoid renumbering conflicts. After any test
produces a result (positive, negative, or inconclusive), add it to the
appropriate section of this file **before** moving on to the next test, so this
document never drifts out of sync with what has actually been verified.
