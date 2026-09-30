# Methodology & Testing Log — Single Source of Truth

> Purpose: this document is the authoritative record of what has actually been
> tested, confirmed, or left open across this assessment. When in doubt about
> project status, this file — not memory of prior conversation — is the
> reference to trust. Update it every time a test is run or a finding is
> written, before moving to the next task.

Last updated: 2026-09-30 (Session covering F-013, F-014, full roadmap Steps 9/10/12 testing, PUT /api/Users/25 anomaly resolution)

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

## 1. Written Findings (Status as of Last Update)

| ID | Title | Severity | Status |
|---|---|---|---|
| F-001 | Sensitive Data Exposure via JWT Payload | High | ✅ Written, committed, pushed |
| F-002 | JWT `alg:none` Signature Bypass — Account Takeover | Critical | ✅ Written, committed, pushed |
| F-003 | Unauthenticated Access to Admin Configuration Endpoint | High | ✅ Written, committed, pushed |
| F-004 | Review Author Field Spoofable + Orphaned Reviews | Medium | ✅ Written, committed, pushed |
| F-005 | IDOR on Checkout — Unauthorized Basket Checkout (+ paymentId/addressId sub-finding) | Critical | ✅ Written, committed, pushed (`6a1a2b0a`) — **confirmed via `git log`, closed** |
| F-006 | SQL Injection — Admin Login Bypass | Critical | ✅ Written, committed, pushed |
| F-007 | SQL Injection — Full User Database Extraction | Critical | ✅ Written, committed, pushed |
| F-008 | NoSQL Operator/Type Confusion in Reviews | Low | ✅ Written, committed, pushed |
| F-009 | DOM-Based XSS via Search Query Parameter (+ confirmed missing CSP) | High | ✅ Written, committed, pushed |
| F-010 | Missing/Inconsistent Security Headers (CSP, Feature-Policy, HSTS) | Low | ✅ Written, committed, pushed (`9aa485d`) |
| F-011 | Verbose SQL Error Disclosure (`/api/Cards/`, `/api/Complaints/`) | Low | ✅ Written, committed, pushed (`9aa485d`) |
| F-012 | Missing RBAC on REST-Scaffolded Endpoints (`/api/Users`, `/api/Feedbacks`) | High | ✅ Written, committed, pushed (`9ffb0f7`) |
| F-013 | Mass Assignment on Registration — Self-Service Admin Account Creation | Critical | 🟡 **Written, presented — NOT yet confirmed saved to local repo or committed.** Last `git status` check showed no F-013 file tracked or untracked; must be re-downloaded and saved to `findings/` before commit. |
| F-014 | Unauthenticated Order Confirmation PDF Disclosure via `/ftp/` Directory Listing | High | ✅ Written, committed, pushed (`598fc7c`) — **confirmed via user's own git push output, closed** |

**Verified via `git log` / user-provided push output** — F-001 through F-012 and F-014 confirmed present in commit history. **F-013 is the one open item in this table** — action needed before it can be marked closed (see Section 6).

`summary.md` (located at `findings/summary.md`, not repo root) has been regenerated to include all 14 findings but is **not yet committed** — confirmed via `git status` showing it as modified/unstaged.

---

## 2. Negative Results (Tested, Confirmed NOT Exploitable — Documented as Notes Within Other Findings, or Standalone Below)

| Test | Result | Documented in |
|---|---|---|
| Stored XSS via review `message` field (`<script>` payload) | Rendered as escaped, inert text — not exploitable | F-009 (negative control) |
| SSRF via `/profile/image/url` (internal admin-config URL as `imageUrl`) | `profileImage` value unchanged after submission — no evidence of server-side fetch | Not written into any finding — deprioritized, see Section 4 |
| Basket **read** IDOR (`GET /rest/basket/8`, User A's token) | Returned `null` — read is protected, unlike checkout | Not yet folded into F-005 — see Section 6 housekeeping |
| Cross-user card read (`GET /api/Cards/8`, User B's token) | `400 "Malicious activity detected"` — protected | Not yet folded into F-005 — see Section 6 housekeeping |
| NoSQL `$where` operator in reviews | Stored inertly, same as `$gt` — no RCE on this endpoint | F-008 |
| Track-order accessed with **zero authentication** | Returned order data with no `Authorization`/`Cookie` at all | Addressed within **F-014** — directory listing independently confirms the same missing-auth pattern with stronger evidence (actual file retrieval, not just tracking metadata) |
| Registration attempt for an already-existing email (`test@gmail.com`) | `400 Bad Request`, `"email must be unique"` — validation working correctly | Not a finding — correct behavior |
| **`PUT /api/Users/25` self-role-escalation** (`{"role":"admin"}`, real customer token) | `401`, `DECODER routines::unsupported` (OpenSSL crash in JWT middleware, not a clean auth rejection). **Reproduced twice** with identical result. Role confirmed unchanged via follow-up `GET /api/Users/25` — record still shows `"role":"customer"`. | **Closed — not a standalone finding.** No working exploit could be demonstrated; the "protection" here is an accidental middleware crash, not a real authorization check, but there is nothing exploitable to write up. Documented here per Section 0 (severity tied to actual impact). |
| **Negative quantity in basket** (`{"quantity":-5}`) | `400 Bad Request` — rejected cleanly | Step 9 testing — no finding |
| **Excessive quantity in basket** (`{"quantity":999999}`) | `400`, `"You can order only up to 5 items of this product."` — per-product cap of 5 enforced server-side | Step 9 testing — no finding |
| **Zero quantity in basket** (`{"quantity":0}`) | `200 OK`, accepted and persisted — item sits in basket contributing $0 to total | Minor data-integrity note only; no exploit path (0 × price = 0, no discount on other items). Not worth a standalone finding. |
| **Forged/invalid coupon at checkout** (`couponData` = base64 of a fake, never-issued code) | `200 OK` — checkout succeeded, but `promotionalAmount: "0"` and `totalPrice` matched full undiscounted price exactly. Coupon was silently ignored, not honored. | Step 9 testing — negative result, no coupon-bypass vulnerability |
| **`.bak` file-extension bypass on `/ftp/`** (null-byte injection, `.bak.md`, uppercase `.BAK`) | All three rejected cleanly (`400`/`403`/`403`) — extension whitelist held under each bypass attempt | Step 12 testing — confirmed negative result; this dead end is what led directly to discovering **F-014** |

---

## 3. Historical Phase Notes (Superseded Terminology)

Earlier sessions used internal "Phase 7 / Phase 8" labels for privilege-escalation
and follow-up testing before the project adopted the clearer Step 4–12 roadmap
(see Section 7). For historical continuity:

- **Former "Phase 7" (privilege escalation testing)** → produced **F-012**, and
  its one open anomaly (`PUT /api/Users/25`) is now resolved — see Section 2
  above. This phase is fully closed.
- **Former "Phase 7 Continuation" (checkout paymentId/addressId ownership test)**
  → resolved as the confirmed Sub-Finding inside **F-005**, now committed and
  pushed (`6a1a2b0a`). Closed.
- **Former "Phase 8" backlog** → its three items have been resolved as follows:
  - Sweep other `/api/<Model>/` routes for missing RBAC → not yet done, still
    open (see Section 5).
  - Price/quantity tampering at checkout → **done**, see Section 2 (negative
    results) above.
  - Regenerate `summary.md` → **done**, pending commit (see Section 1/6).

All further phase tracking below uses the Step 4–12 roadmap terminology only,
to avoid reintroducing the ambiguity this section was created to resolve.

---

## 4. Confirmed But Homeless (tested, real result, not yet written into any finding file)

| Item | Result | Status |
|---|---|---|
| SSRF probe via `/profile/image/url` | Negative — no evidence of server-side fetch | Still homeless — deprioritized; low value to write up given the negative result |
| `GET /api/Cards/8` cross-user block | Positive control — access denied correctly | Still pending write-up as a note into F-005 |
| Basket read IDOR protection | Positive control — access denied correctly | Still pending write-up as a note into F-005 |
| Stack trace disclosure on `/api/Users/25` PUT 401 error (`Express ^4.22.1`, internal `UnauthorizedError` class name, full file paths) | Confirmed, reproduced twice | **Explicitly deprioritized by project owner** — decided not to add to F-011 to keep momentum. Documented here as a known, intentionally-skipped addition rather than an oversight. |
| Stack trace disclosure on `/profile/image/file` upload errors (`profileImageFileUpload.js`, two distinct error paths: "Illegal file type" and "Blocked illegal activity by ::ffff:...") | Confirmed, two distinct crash points observed | **Explicitly deprioritized by project owner** — same reasoning as above; a fourth confirmed instance of the same F-011 error-disclosure pattern, intentionally left out of the write-up. |

---

## 5. Not Yet Started / Known Gaps

With all 9 roadmap steps (Section 7) now tested at least once, the remaining
open items are narrow, specific gaps rather than untested phases:

- [ ] Sweep other `/api/<Model>/` routes (`Addresss`, `Products`, `BasketItems`)
      for the same missing-RBAC pattern F-012 found — F-012's own stated
      Follow-Up Testing item, never executed.
- [ ] Deluxe membership business logic (the odd `GET` `400` / `POST` `200`
      behavior flagged during initial recon) — part of Step 9's original scope,
      never actually tested; quantity and coupon testing were completed instead.
- [ ] File-upload path-traversal filename test (e.g.
      `filename="../../../../etc/passwd.jpg"`) on `/profile/image/file` —
      part of Step 10's original scope, planned but dropped when establishing
      a clean real-image baseline via curl proved impractical mid-session.
- [ ] Independently re-fetch `order_57f7-1c0b9e56477137e4.pdf` directly (only
      its listing metadata was confirmed, not its raw content) — F-014 Follow-
      Up Testing item.
- [ ] A second, reverse-direction confirmatory run of F-005's paymentId/
      addressId sub-finding, recommended (not required) before final sign-off.
- [ ] Test whether other `User` model fields (`isActive`, `deluxeToken`,
      `lastLoginIp`) are similarly mass-assignable via registration — F-013
      Follow-Up Testing item.

None of these block calling the roadmap complete (see Section 7) — they are
depth-of-evidence extensions on already-confirmed findings, or narrow scope
items within an already-tested phase, not missing coverage of an entire step.

---

## 6. Housekeeping Debt (not testing — paperwork)

- [x] Confirm F-010 and F-011 committed and pushed — verified, commit `9aa485d`
- [x] Confirm F-012 committed and pushed — verified, commit `9ffb0f7`
- [x] Commit and push the updated F-005 (paymentId/addressId sub-finding) —
      **done**, verified via `git log`, commit `6a1a2b0a`
- [x] Commit and push F-014 — **done**, verified via user's own push output,
      commit `598fc7c`
- [ ] **Save F-013 to `findings/F-013-mass-assignment-admin-registration.md`,
      then commit and push** — file has been written and presented but is
      confirmed absent from the local repo as of the last `git status` check.
      This is the single most important open action item right now.
- [ ] Commit and push the regenerated `summary.md` (at `findings/summary.md`)
      — file is ready and modified locally, not yet committed. Should be
      committed in the **same commit as F-013** per project convention (file +
      log/summary together, as done previously for F-005).
- [ ] Add the F-005 positive-control notes (basket read, card read) into
      F-005's file
- [ ] Regenerate `summary.md` further if any additional findings are added
      after this point — otherwise current version is final

---

## 7. Full Testing Roadmap Status (Step 4–12)

| Step | Scope | Status |
|---|---|---|
| Step 4 | Auth & Session (JWT, login, cookies) | ✅ Done — F-001, F-002, F-003 |
| Step 5 | Authorization / IDOR | ✅ Done — F-004, F-005 (+ sub-finding) |
| Step 6 | Injection (SQLi/NoSQLi) | ✅ Done — F-006, F-007, F-008 |
| Step 7 | XSS | ✅ Done — F-009 |
| Step 8 | API-specific abuse (mass assignment, excessive data exposure) | ✅ Done — F-012, F-013 |
| Step 9 | Business logic (price/quantity, coupons, deluxe membership) | ✅ Done — quantity and coupon abuse tested (negative results); deluxe membership logic not tested (see Section 5) |
| Step 10 | File upload / SSRF | ✅ Done — SSRF tested (negative); file-type validation tested (inconclusive — no clean baseline established); path traversal not tested (see Section 5) |
| Step 11 | Misconfiguration / headers | ✅ Done — F-010, F-011 |
| Step 12 | Outdated/vulnerable components | ✅ Done — `.bak` extension bypass tested and confirmed negative; led directly to discovering F-014 |

**All 9 roadmap phases have been tested at least once.** Remaining work is
limited to the specific, narrow gaps listed in Section 5 and the housekeeping
items in Section 6 — not any untested phase.

---

## How to use this file going forward

Before starting any new test, check Section 5 first — it represents the actual
current frontier of the project. Before writing any new finding, check Section 1
to confirm the next available ID and avoid renumbering conflicts. After any test
produces a result (positive, negative, or inconclusive), add it to the
appropriate section of this file **before** moving on to the next test, so this
document never drifts out of sync with what has actually been verified. Every
finding must clear Section 0's verification standard before being marked
Confirmed.
