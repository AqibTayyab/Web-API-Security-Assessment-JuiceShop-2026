<div align="center">

# 🔐 Web & API Security Assessment
### OWASP Juice Shop | Full Black Box Penetration Test

<br>

![Findings](https://img.shields.io/badge/Findings-14_Confirmed-red?style=for-the-badge)
![Critical](https://img.shields.io/badge/Critical-5-8B0000?style=for-the-badge)
![High](https://img.shields.io/badge/High-5-FF4500?style=for-the-badge)
![Medium](https://img.shields.io/badge/Medium-1-FFA500?style=for-the-badge)
![Low](https://img.shields.io/badge/Low-3-FFD700?style=for-the-badge)

![Target](https://img.shields.io/badge/Target-OWASP_Juice_Shop-brightgreen?style=flat-square)
![Method](https://img.shields.io/badge/Methodology-PTES_Aligned-blue?style=flat-square)
![Tools](https://img.shields.io/badge/Tooling-Burp_Suite-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Complete-success?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

<br>

A complete, evidence backed penetration test conducted end to end, from a signed scope document through reconnaissance, structured testing, and professionally written findings with real remediation guidance.

</div>

<br>

## 📋 Table of Contents

- [Overview](#-overview)
- [Findings At a Glance](#-findings-at-a-glance)
- [Featured Vulnerabilities](#-featured-vulnerabilities)
- [Repository Structure](#-repository-structure)
- [Methodology](#-methodology)
- [Tooling](#-tooling)
- [Scope](#-scope)
- [About This Project](#-about-this-project)

<br>

## 🧭 Overview

This repository documents a full security assessment of **OWASP Juice Shop**, a deliberately vulnerable web application maintained by OWASP for training and tool evaluation. The engagement was run the way a real paid assessment would be, starting with a written scope and authorization record, moving through reconnaissance and attack surface mapping, then structured testing across the OWASP Top 10, and ending with fourteen fully documented, evidence backed findings.

Every finding includes reproduction steps, raw request and response evidence, a root cause explanation, an impact assessment, CVSS scoring where applicable, CWE classification, and concrete remediation guidance.

<br>

## 📊 Findings At a Glance

<div align="center">

| Severity | Count | Findings |
|:---:|:---:|:---|
| 🔴 **Critical** | 5 | F-002, F-005, F-006, F-007, F-013 |
| 🟠 **High** | 5 | F-001, F-003, F-009, F-012, F-014 |
| 🟡 **Medium** | 1 | F-004 |
| 🟢 **Low** | 3 | F-008, F-010, F-011 |

</div>

<br>

## ⭐ Featured Vulnerabilities

<table>
<tr>
<td width="50%" valign="top">

### 🟥 F-013 · Mass Assignment
**Self Service Admin Registration**

One extra field on a public signup form, and any anonymous visitor walks away with a fully privileged administrator account. No injection. No forged token. No existing account required.

[Read the full report →](findings/F-013-mass-assignment-admin-registration.md)

</td>
<td width="50%" valign="top">

### 🟥 F-007 · SQL Injection
**Full Database Extraction**

A UNION based injection through the public search bar pulls every user's email, password hash, role, and membership token out of the database in a single request.

[Read the full report →](findings/F-007-sqli-full-database-extraction.md)

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🟥 F-002 · Broken Authentication
**JWT alg:none Bypass**

The session token verification never actually checks the signature. A hand forged, unsigned token claiming to be any user is accepted as valid, enabling full account takeover.

[Read the full report →](findings/F-002-jwt-alg-none-account-takeover.md)

</td>
<td width="50%" valign="top">

### 🟥 F-005 · Broken Access Control
**Checkout IDOR**

Any logged in user can force checkout on another user's basket, and independently, attach someone else's saved payment card and address to their own order.

[Read the full report →](findings/F-005-idor-unauthorized-checkout.md)

</td>
</tr>
</table>

<details>
<summary><b>📁 View all 14 findings</b></summary>

<br>

| ID | Finding | Severity | OWASP Category |
|:---|:---|:---:|:---|
| [F-001](findings/F-001-sensitive-data-exposure-jwt.md) | Sensitive Data Exposure via JWT Payload | High | A02 Cryptographic Failures |
| [F-002](findings/F-002-jwt-alg-none-account-takeover.md) | JWT alg:none Signature Bypass | Critical | A07 Auth Failures |
| [F-003](findings/F-003-unauthenticated-admin-config.md) | Unauthenticated Admin Config Access | High | A01 Broken Access Control |
| [F-004](findings/F-004-review-injection-corrected.md) | Review Author Spoofing | Medium | A04 Insecure Design |
| [F-005](findings/F-005-idor-unauthorized-checkout.md) | IDOR on Checkout | Critical | A01 Broken Access Control |
| [F-006](findings/F-006-sqli-admin-login-bypass.md) | SQL Injection Login Bypass | Critical | A03 Injection |
| [F-007](findings/F-007-sqli-full-database-extraction.md) | Full Database Extraction | Critical | A03 Injection |
| [F-008](findings/F-008-nosql-type-confusion-reviews.md) | NoSQL Type Confusion | Low | A03 Injection |
| [F-009](findings/F-009-dom-xss-search-query.md) | DOM Based XSS in Search | High | A03 Injection |
| [F-010](findings/F-010-missing-security-headers.md) | Missing Security Headers | Low | A05 Misconfiguration |
| [F-011](findings/F-011-verbose-sql-error-disclosure.md) | Verbose SQL Error Disclosure | Low | A05 Misconfiguration |
| [F-012](findings/F-012-missing-rbac-rest-endpoints.md) | Missing RBAC on REST Endpoints | High | A01 Broken Access Control |
| [F-013](findings/F-013-mass-assignment-admin-registration.md) | Mass Assignment Admin Registration | Critical | A08 Data Integrity Failures |
| [F-014](findings/F-014-unauthenticated-order-pdf-disclosure.md) | Order PDF Disclosure | High | A01 Broken Access Control |

Full severity breakdown and cross finding analysis in [summary.md](summary.md).

</details>

<br>

## 🗂 Repository Structure

```
├── scope-and-authorization.md      Signed scope, rules of engagement, authorization
├── attack-surface-map.md           Recon findings, endpoint inventory, test priorities
├── methodology-tracking-log.md     Full testing log, verification standard, open items
├── summary.md                      Master findings table and cross finding analysis
└── findings/
    ├── F-001-sensitive-data-exposure-jwt.md
    ├── F-002-jwt-alg-none-account-takeover.md
    ├── ...
    └── F-014-unauthenticated-order-pdf-disclosure.md
```

<br>

## 🔬 Methodology

Testing followed a structured nine phase roadmap.

```
Authentication & Session   →   Authorization & IDOR   →   Injection (SQL / NoSQL)
        ↓                              ↓                           ↓
Cross Site Scripting   →   API Specific Abuse   →   Business Logic
        ↓                              ↓                           ↓
File Upload & SSRF   →   Security Misconfiguration   →   Outdated Components
```

Every finding was held to an explicit verification standard before being marked confirmed. That meant raw request and response evidence rather than assumption, a negative control baseline wherever relevant, reproducibility across more than one attempt, and severity tied to demonstrated impact rather than how interesting a bug looked on the surface. Several confirmed negative results are documented alongside the positive findings, since knowing what genuinely is not exploitable is part of a credible assessment, not just the wins.

Full detail in [methodology-tracking-log.md](methodology-tracking-log.md).

<br>

## 🛠 Tooling

<div align="left">

![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=flat-square&logo=burpsuite&logoColor=white)
![cURL](https://img.shields.io/badge/cURL-073551?style=flat-square&logo=curl&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white)

</div>

Burp Suite Community Edition for interception and request manipulation, browser developer tools for client side analysis, curl and Python for scripted verification, and manual JWT construction for the authentication bypass testing.

<br>

## 🎯 Scope

This assessment targets a local, self hosted instance of OWASP Juice Shop only. No public or third party systems were tested at any point. Full scope, exclusions, and rules of engagement are documented in [scope-and-authorization.md](scope-and-authorization.md).

> OWASP Juice Shop is distributed under the MIT license explicitly for security training and tool evaluation. Every finding here describes a known, intentional training vulnerability, not an undisclosed flaw in production software, which is why CWE classification is used throughout instead of CVE.

<br>

## 👤 About This Project

Built as a self directed portfolio project to practice the full lifecycle of a professional penetration test, not just the exploitation part. The scope document, the recon phase, the verification discipline, and the written reports were treated as seriously as the vulnerabilities themselves.

<div align="center">
<br>

**If this was useful or interesting, a star on the repo is appreciated.**

</div>

<br>

### Connect with Me

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=16&pause=1200&color=00FF41&background=0D1117&center=true&vCenter=true&width=550&lines=Let's+connect+and+build+something+secure.;Open+to+AppSec+%2F+Purple+Team+opportunities." alt="Typing SVG" />
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/muhammad-aqib-tayyab-ethical-hacker">LinkedIn</a> ·
  <a href="https://github.com/AqibTayyab">GitHub</a> ·
  <a href="https://www.youtube.com/@MuhammadAqibTayyab">YouTube</a> ·
</p>

<p align="center"><i>From AqibTayyab. Let's shift the focus from certificates to verifiable, shared knowledge.</i></p>
