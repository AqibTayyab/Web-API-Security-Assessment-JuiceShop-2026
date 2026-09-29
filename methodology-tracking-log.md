# Methodology & Testing Log — Single Source of Truth

> Purpose: this document is the authoritative record of what has actually been
> tested, confirmed, or left open across this assessment. When in doubt about
> project status, this file — not memory of prior conversation — is the
> reference to trust. Update it every time a test is run or a finding is
> written, before moving to the next task.

Last updated: 2026-09-29 (Session covering F-012 push confirmation + F-005 paymentId/addressId sub-finding)

---

## 0. Verification Standard (applies to every finding, before it is marked Confirmed)

Every finding in this project must clear all five checks below before being
written up or marked Confirmed. This exists specifically to avoid overhyping a
result or calling something a vulnerability when it isn't one.

1. **Raw evidence, not inference** — actual request/response pairs, not "this
   probably means X."
2. **A negative control or baseline, where relevant** — test the thing that
   *should* fail alongside the thing that succeeds (e.g. F-004's disproven
   edit-IDOR hypothesis, F-009's inert `<script>` vs. executing `<iframe>`,
   F-012's forged-vs-real-token identical response).
3. **Reproducibility** — shown at least twice, or across two accounts/sessions,
   before calling a result consistent (as done for F-011). A single clean run
   with independently-verified inputs (IDs confirmed via a separate GET before
   use, not assumed) is acceptable to mark a finding Confirmed, but a second
   confirmatory run is recommended before final report sign-off if only one
   run has been performed.
4. **Severity tied to actual impact, not to how interesting the bug is** — e.g.
   F-008 was kept at Low specifically because the operator injection never
   reached a query context; that instinct should be applied consistently going
   forward, not just to that one finding.
5. **A concrete CWE/OWASP mapping that actually fits the mechanism**, not the
   closest-sounding category.

---

## 1. Written, Committed Findings (Confirmed, Documented, Pushed)

| ID | Title | Severity | Status |
|---|---|---|---|
| F-001 | Sensitive Data Exposure via JWT Payload | High | ✅ Written, committed |
| F-002 | JWT `alg:none` Signature Bypass — Account Takeover | Critical | ✅ Written, committed |
| F-003 | Unauthenticated Access to Admin Configuration Endpoint | High | ✅ Written, committed |
| F-004 | Review Author Field Spoofable + Orphaned Reviews | Medium | ✅ Written, committed |
| F-005 | IDOR on Checkout — Unauthorized Basket Checkout (+ paymentId/addressId sub-finding) | Critical | ✅ Written, committed — **sub-finding added, needs commit/push confirmation** |
| F-006 | SQL Injection — Admin Login Bypass | Critical | ✅ Written, committed |
| F-007 | SQL Injection — Full User Database Extraction | Critical | ✅ Written, committed |
| F-008 | NoSQL Operator/Type Confusion in Reviews | Low | ✅ Written, committed |
| F-009 | DOM-Based XSS via Search Query Parameter (+ confirmed missing CSP) | High | ✅ Written, committed |
| F-010 | Missing/Inconsistent Security Headers (CSP, Feature-Policy, HSTS) | Low | ✅ Written, committed, pushed (`9aa485d`) |
| F-011 | Verbose SQL Error Disclosure (`/api/Cards/`, `/api/Complaints/`) | Low | ✅ Written, committed, pushed (`9aa485d`) |
| F-012 | Missing RBAC on REST-Scaffolded Endpoints (`/api/Users`, `/api/Feedbacks`) | High | ✅ Written, committed, pushed (`9ffb0f7`) — **confirmed via `git log`, closed** |

**Verified via `git log --oneline -- findings/`** — files confirmed present in
commit history through `9ffb0f7`. No action needed on F-001–F-004, F-006–F-012.
F-005 needs its updated version (with the new sub-finding below) committed and
pushed before it can be marked fully closed.

---

## 2. Negative Results (Tested, Confirmed NOT Exploitable — Documented as Notes Within Other Findings, Not Standalone)

These are real, useful results but were folded into related findings rather than given their own ID:

| Test | Result | Documented in |
|---|---|---|
| Stored XSS via review `message` field (`<script>` payload) | Rendered as escaped, inert text — not exploitable | F-009 (negative control) |
| SSRF via `/profile/image/url` (internal admin-config URL as `imageUrl`) | `profileImage` value unchanged after submission — no evidence of server-side fetch | Not yet written into any finding — **still needs a home**, see Section 4 |
| Basket **read** IDOR (`GET /rest/basket/8`, User A's token) | Returned `null` — read is protected, unlike checkout | **Still pending write-up into F-005** — see Section 6 housekeeping |
| Cross-user card read (`GET /api/Cards/8`, User B's token) | `400 "Malicious activity detected"` — protected | **Still pending write-up into F-005** — see Section 6 housekeeping |
| NoSQL `$where` operator in reviews | Stored inertly, same as `$gt` — no RCE on this endpoint | F-008 |
| Track-order accessed with **zero authentication** | Returned order data with no `Authorization`/`Cookie` at all | Confirmed, **not yet written anywhere** — likely intentional by-design (standard "track my order" UX pattern), not a bug on its own unless codes are guessable (untested, see Section 4) |
| Registration attempt for an already-existing email (`test@gmail.com`) | `400 Bad Request`, `"email must be unique"` — validation working correctly | Not a finding — negative result, noted here only to confirm it was correctly excluded |

---

## 3. Phase 7 — Privilege Escalation Testing (produced F-012; three items remain open)

**Original goal:** determine whether a forged `alg:none` JWT with `"role":"admin"` injected can bypass role-based access control anywhere in the app (following directly from the F-002 technique).

**What actually happened, in order:**

1. **`GET /api/Users`** — tested with both a real, unmodified customer token AND the forged admin-role token. **Both succeeded identically**, returning the full user table (all emails, roles, deluxe tokens). **Conclusion: this endpoint has no role check at all.** Written up as F-012.

2. **`DELETE /api/Feedbacks/1`** — tested with the real customer token first (meant as a "baseline expected to fail"). **It succeeded** (`200 OK`, record deleted) — no forgery needed. Written up as F-012.

3. **`PUT /api/Users/25`** (attempting self-role-escalation via a normal `PUT`) — tested with the real customer token. Result: `401 Unauthorized`, but with error `DECODER routines::unsupported` — an **OpenSSL key-parsing failure**, not a clean authorization rejection. **This result is NOT interpretable as evidence of role protection working** — it needs isolated follow-up before any conclusion is drawn. **Still open — see Section 5.**

**Current state:** items 1 and 2 above are written up as **F-012** (see Section 1, confirmed pushed at `9ffb0f7`). Item 3 remains an open, uninterpreted anomaly.

---

## 3a. Phase 7 Continuation — Checkout paymentId/addressId Ownership Test (CONFIRMED)

**Goal:** resolve the open question flagged in F-005's own Follow-Up Testing —
whether `paymentId`/`addressId` in the checkout body are validated as belonging
to the authenticated user, independent of the basket-ownership issue F-005
already proved.

**Method:**
1. Confirmed, via `GET /api/Cards` and `GET /api/Addresss` (Account 2's own
   token), that card `id: 7` and address `id: 8` belong to Account 2
   (`id: 26`, `UserId` field confirmed in response).
2. As Account 1 (`id: 25`, own basket `bid: 6`), added an item to their own
   basket, then submitted checkout with `paymentId: "7"` and `addressId: "8"`
   — both belonging to Account 2, not Account 1.
3. **Result:** `200 OK`, `orderConfirmation: "1aed-18b1f1f329bf8830"` — checkout
   succeeded using another user's saved payment card and address, with no
   ownership check at all.

**Status:** Confirmed via one clean, fully-evidenced run (IDs independently
verified before use, not assumed). Written up as a Sub-Finding inside F-005 —
**pending commit/push**. Per Section 0's verification standard, a second
confirmatory run (reverse direction) is recommended before final report
sign-off, though not required to mark this Confirmed.

---

## 4. Confirmed But Homeless (tested, real result, not yet written into any finding file)

| Item | Result | Recommended home |
|---|---|---|
| SSRF probe via `/profile/image/url` | Negative — no evidence of server-side fetch | New short finding, or a "Follow-Up Testing" note if scored not worth a full write-up |
| `GET /api/Cards/8` cross-user block | Positive control — access denied correctly | Should be added as a note to F-005 (contrasts with checkout's lack of protection) — **still pending, see Section 6** |
| Basket read IDOR protection | Positive control — access denied correctly | Should be added as a note to F-005 — **still pending, see Section 6** |
| Track-order with zero auth | By-design, not yet a finding | Needs 2-3 more tracking codes compared for predictability before deciding if it's F-0XX (enumeration) or just a summary note |
| `PUT /api/Users/25` OpenSSL decoder error | Anomaly, uninterpreted | Needs isolated retesting — is this route-specific, or does the same error occur on other `PUT`/`PATCH` admin-shaped routes? |
| Stack trace disclosure on `/api/Users/25` 401 error (`Express ^4.22.1` + internal error class name) | Confirmed | Should be added as a one-line note to F-011 (same error-disclosure theme, different layer — middleware vs. database) — **still pending, see Section 6** |

---

## 5. Not Yet Started (Phase 7 remainder + Phase 8 backlog — kept separate below to avoid the ambiguity in prior versions of this log)

**Phase 7 remainder (direct continuation of the privilege-escalation testing above):**
- [ ] Isolate and explain the `PUT /api/Users/25` OpenSSL decoder anomaly
- [ ] Track-order code enumeration/predictability (need 3-4 codes compared side by side)
- [ ] Decide fate of the remaining "confirmed but homeless" items in Section 4 (SSRF probe, and the two positive-control notes still pending write-up)

**Phase 8 (new, separate testing — not a continuation of Phase 7):**
- [ ] Systematically sweep other `/api/<Model>/` routes for the same missing-RBAC pattern F-012 found (e.g., `Addresss`, `Products`, `BasketItems`) — this is F-012's own stated Follow-Up Testing item, distinct from the Phase 7 privilege-escalation work
- [ ] Price/quantity tampering within the checkout body itself — flagged in F-005's Follow-Up Testing as its own separate business-logic test, distinct from the ownership-check work just completed
- [ ] Regenerate `summary.md` once all of the above is finalized — **intentionally deferred until the end, per project decision**

---

## 6. Housekeeping Debt (not testing — paperwork)

- [x] Confirm F-010 and F-011 are actually committed and pushed to GitHub — **verified via `git log`, commit `9aa485d`**
- [x] Confirm F-012 committed and pushed — **verified via `git log`, commit `9ffb0f7`**
- [ ] Commit and push the updated F-005 (with the new paymentId/addressId sub-finding) — **file ready, not yet pushed**
- [ ] Add the F-005 positive-control notes (basket read, card read) into F-005's file — **not yet done; can be folded into the same commit as the sub-finding above**
- [ ] Add the stack-trace disclosure note into F-011's file
- [ ] Regenerate `summary.md` once all of the above is finalized — **intentionally deferred until the end, per project decision**

---

## How to use this file going forward

Before starting any new test, check Sections 3–5 first — they represent the actual
current frontier of the project. Before writing any new finding, check Section 1
to confirm the next available ID and avoid renumbering conflicts. After any test
produces a result (positive, negative, or inconclusive), add it to the
appropriate section of this file **before** moving on to the next test, so this
document never drifts out of sync with what has actually been verified. Every
finding must clear Section 0's verification standard before being marked
Confirmed.
