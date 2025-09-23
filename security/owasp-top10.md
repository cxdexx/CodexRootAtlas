# OWASP Top 10 2025 — Detailed Dev & Lab Reference

For each Top-10 item this file contains:

* **Factors** (why it happens)
* **Overview** (short elevator pitch)
* **Description** (what it looks like in the wild)
* **How to Prevent** (practical, actionable mitigations)
* **Example Attack Scenarios** (lab-safe PoCs and workflows)
* **References** (authoritative further reading)
* **List of Mapped CWEs** (common CWE numbers associated with this category)

> Use PoCs only against lab targets (Juice Shop, DVWA, TryHackMe boxes, HTB retired boxes) or systems you explicitly own/have written permission to test. Never run these against production or third-party targets without a signed engagement.

---

## Table of contents

1. [A01 — Broken Access Control](#a01---broken-access-control)
2. [A02 — Cryptographic Failures](#a02---cryptographic-failures)
3. [A03 — Injection](#a03---injection)
4. [A04 — Insecure Design](#a04---insecure-design)
5. [A05 — Security Misconfiguration](#a05---security-misconfiguration)
6. [A06 — Vulnerable & Outdated Components](#a06---vulnerable--outdated-components)
7. [A07 — Identification & Authentication Failures](#a07---identification--authentication-failures)
8. [A08 — Software & Data Integrity Failures](#a08---software--data-integrity-failures)
9. [A09 — Security Logging & Monitoring Failures](#a09---security-logging--monitoring-failures)
10. [A10 — Server-Side Request Forgery (SSRF)](#a10---server-side-request-forgery-ssrf)

Appendices:

* [Practical testing commands & lab checklist](#practical-testing-commands--lab-checklist)
* [Semgrep starter rules](#semgrep-starter-rules)
* [One-page cheat sheet (printable)](#one-page-cheat-sheet-printable)
* [Commit & PR suggestion](#commit--pr-suggestion)

---

# How to use this file

* Read the **Overview** for quick understanding, then read **How to Prevent** to pick immediate fixes.
* Copy the **Example Attack Scenarios** into your lab notes as sanitized PoCs (only lab targets).
* When producing client findings, paste the short "Finding / Impact / Remediation" blocks into your report and adapt severity.
* The **Mapped CWEs** are suggested examples to index findings to CWE categories in reports.

---

## A01 — Broken Access Control

**Factors**

* Missing server-side authorization checks.
* Trusting client-side controls (HTML/JS gating).
* Predictable or enumerable resource identifiers (IDs, filenames).
* Overbroad permissions for service accounts or APIs.

**Overview**
Broken access control occurs when an application allows a user to act outside their intended permissions — reading or modifying data belonging to others, or performing privileged actions.

**Description**
Common symptoms: endpoints that return data for arbitrary resource IDs, admin-only pages accessible by non-admin users when changing a parameter, or actions succeeding when they should be denied.

**How to Prevent**

* Enforce authorization on the server for **every** request (deny by default).
* Use object-level access checks (owner vs requestor) and role/attribute-based access controls.
* Avoid exposing real internal IDs; consider using opaque identifiers (UUIDs, surrogate keys) where appropriate.
* Harden APIs: validate `scope`/`aud` claims in tokens; use least privilege for service accounts.
* Automate tests that verify unauthorized users receive `403/401` for protected endpoints.

**Example Attack Scenarios (lab-safe)**

* *Horizontal escalation (Juice Shop)*: Login as user A → GET `/api/user/5/orders` → change path to `/api/user/6/orders` → server returns user B orders (PoC in lab).
* *Vertical escalation via API*: Non-admin user calls `POST /admin/feature-toggle` with modified JSON; server applies change (shows lack of role checks).

**Testing commands / tactics**

* Burp Repeater: modify `id` path/query and compare responses.
* Burp Intruder: fuzz numeric IDs to find valid ranges.
* Write unit/integration tests that assert authorization for each route.

**References**

* OWASP: Broken Access Control (Top 10).
* Example article: resource-based access control patterns (search OWASP docs).

**List of Mapped CWEs (common examples)**

* CWE-284: Improper Access Control
* CWE-285: Improper Authorization
* CWE-639: Authorization Bypass Through User-Controlled Key (example)

---

## A02 — Cryptographic Failures

**Factors**

* Rolling your own crypto or using deprecated algorithms.
* Storing secrets in source code or unprotected config files.
* Missing TLS enforcement or poor certificate validation.
* Poor password storage practices (plaintext or weak hashing).

**Overview**
Cryptographic Failures refers to weaknesses in how data is protected in transit and at rest (encryption, hashing, key management).

**Description**
Symptoms: plaintext passwords, missing TLS, tokens signed with weak algorithms, or secrets stored in `.env` committed to a repo.

**How to Prevent**

* Enforce TLS (HTTPS) site-wide; HSTS header and secure cookie flags.
* Use established libraries (e.g., `bcrypt`, `argon2`) for password hashing; use per-user salts and adequate cost factors.
* Avoid custom crypto; use vetted protocols and libs.
* Store secrets in secure secret stores (Vault, KMS); do not commit them.
* Manage and rotate keys; use short-lived tokens when possible.

**Example Attack Scenarios (lab-safe)**

* *Credential harvest via DB dump (lab)*: Inspect local DB and find plaintext passwords; show how easily accounts can be compromised (reset and reissue in lab).
* *Token forgery demo (lab)*: Use weak secret (e.g., `secret`) used to sign JWTs and demonstrate token recreation (lab-only).

**Testing commands / tactics**

* `curl -I https://yourlab.local` — check for `Strict-Transport-Security`.
* Inspect cookies: are they `Secure; HttpOnly; SameSite`?
* `npm audit` or `snyk` can also surface weak crypto use via vulnerable packages.

**References**

* OWASP Cryptographic Storage Cheat Sheet.
* NIST guidance for hashing & key management.

**List of Mapped CWEs**

* CWE-310: Cryptographic Issues
* CWE-326: Inadequate Encryption Strength
* CWE-321: Use of Hard-coded Cryptographic Key

---

## A03 — Injection

**Factors**

* Unsanitized input concatenated into queries/commands.
* Use of dynamic query building without parameterization.
* Excessive privileges for DB/service accounts.

**Overview**
Injection occurs when untrusted input is interpreted as part of a command or query (SQL, OS, LDAP, NoSQL, XPATH, etc).

**Description**
Typical: SQL injection (user input ends up in SQL), OS command injection via shelling out with user data, or template injection.

**How to Prevent**

* Use parameterized queries / prepared statements / ORM parameter binding.
* Validate and strongly type inputs at the boundary.
* Use least privilege DB accounts.
* Apply input length and character set restrictions when appropriate.
* Use output encoding for context (HTML, JS, URL) — do not rely solely on input sanitization.

**Example Attack Scenarios (lab-safe)**

* *SQL Injection (lab)*: `sqlmap -u "http://localhost:3000/item?id=1" --batch --dbs` (only on lab).
* *OS Command Injection (lab)*: app accepts filename; payload `; cat /etc/passwd` in lab demonstrates dangerous shell execution.

**Testing commands / tactics**

* Burp Intruder with SQL payloads.
* `sqlmap` (lab-only).
* grep server code for string concatenation in DB calls.

**References**

* OWASP: Injection Prevention Cheat Sheet.
* PortSwigger SQLi labs.

**List of Mapped CWEs**

* CWE-89: SQL Injection
* CWE-78: OS Command Injection
* CWE-74: Improper Neutralization of Special Elements (Injection)

---

## A04 — Insecure Design

**Factors**

* No threat modeling or security requirements during design.
* Business logic not reviewed from an attacker’s POV.
* Missing design-level mitigations (rate-limits, MFA, segregation).

**Overview**
Insecure design is about systemic architectural weaknesses rather than single implementation bugs. These stem from design choices that create exploitable conditions.

**Description**
Examples: no rate-limit on password endpoints, public debug features, or an overly-permissive microservice mesh.

**How to Prevent**

* Integrate threat modeling (STRIDE/PASTA) into design sprints.
* Define security requirements and acceptance criteria per feature.
* Adopt secure design patterns: fail-safe defaults, defense-in-depth, least privilege.
* Use design reviews and red-team exercises focusing on business logic abuse.

**Example Attack Scenarios (lab-safe)**

* *Business logic abuse*: purchase flow lacks quantity checks → attacker manipulates client to create negative prices in lab orders (demonstration only in lab).
* *No rate-limits*: automate login attempts in lab to show account lockout absent.

**Testing commands / tactics**

* Design review checklists.
* Automated abuse-case simulation scripts in controlled lab.

**References**

* Threat modeling resources (OWASP, Microsoft Threat Modeling).
* Articles on secure design patterns.

**List of Mapped CWEs**

* (Insecure Design maps to multiple CWEs depending on manifestation; common examples):

  * CWE-640: Weak Password Recovery
  * CWE-613: Insufficient Session Expiration
  * (Design-level issues often map to business-logic specific CWEs.)

---

## A05 — Security Misconfiguration

**Factors**

* Manual configuration drift, dev configs in prod.
* Default credentials left in place.
* Over-privileged services and exposed management endpoints.

**Overview**
Security misconfiguration is broad: any improper or insecure configuration that leaves the system more exposed than necessary.

**Description**
Symptoms: default admin accounts, directory listing enabled, debug stack traces visible, excessive permissions on cloud buckets.

**How to Prevent**

* Adopt immutable infrastructure and automated configuration management (Ansible, Terraform).
* Harden images (CIS benchmarks), remove default accounts, disable debug.
* Implement automated scans for exposed configs and endpoints.
* Use environment-specific config with secrets management and vaulting.

**Example Attack Scenarios (lab-safe)**

* *Exposed `.git` or `.env` via misconfigured server*: show retrieving dev secrets in a lab environment.
* *Debug endpoints active*: triggering `/debug` returns database connection info (lab-only proof).

**Testing commands / tactics**

* `nikto -h http://localhost:3000` (lab).
* `curl -I` to check headers.
* Check for open ports and services with `nmap`.

**References**

* OWASP Server Hardening and Security Misconfiguration docs.

**List of Mapped CWEs**

* CWE-933: Insufficiently Protected Credentials? (examples vary)
* CWE-732: Incorrect Permission Assignment for Critical Resource
* CWE-200: Information Exposure

---

## A06 — Vulnerable & Outdated Components

**Factors**

* Lack of dependency hygiene, ignoring security bulletins.
* Transitive dependencies not tracked.
* Using heavyweight or monolithic base images with outdated libs.

**Overview**
Using components with known vulnerabilities creates an easy path for attackers (supply chain & runtime exploit).

**Description**
Library crates, package managers, and docker images may contain public CVEs. Symptoms: Dependabot alerts, `npm audit` findings.

**How to Prevent**

* Enable automated dependency scanning (Dependabot, Snyk) and run `npm audit`, `pip-audit`.
* Pin versions in lockfiles and review transitive dependencies.
* Use minimal base images and rebuild images regularly.
* Adopt supply chain controls (signing, SBOMs).

**Example Attack Scenarios (lab-safe)**

* *Known RCE in package used locally*: update package, test exploit in lab to illustrate the severity (lab-only).
* *Malicious dependency injection demo*: in a local staging repo, show how an unreviewed package can run arbitrary code (lab-only).

**Testing commands / tactics**

* `npm audit` / `yarn audit` / `pip-audit`
* `docker scan`
* Integrate dependency checks into CI and require PRs for upgrades.

**References**

* OWASP: Using Components with Known Vulnerabilities
* NPM and PyPI security best practices.

**List of Mapped CWEs**

* CWE-1104: Use of Unmaintained Third-Party Components
* CWE-494: Download of Code Without Integrity Check
* CWE-829: Inclusion of Functionality from Unknown Source

---

## A07 — Identification & Authentication Failures

**Factors**

* Weak default auth or missing brute-force protections.
* Insecure session management, predictable tokens.
* No multi-factor authentication for sensitive flows.

**Overview**
Authentication flaws allow attackers to assume other identities or extend session lifetimes beyond intended.

**Description**
Examples: session IDs in URLs, tokens that never expire, logins without rate limits, or missing account lockout.

**How to Prevent**

* Use secure authentication frameworks and proven libraries.
* Rotate session identifiers on auth events and privilege changes.
* Use short token lifetimes and refresh tokens with revocation support.
* Implement MFA for admin or sensitive operations.
* Enforce strong password policies (length, complexity, checks against known-breached lists).

**Example Attack Scenarios (lab-safe)**

* *Session fixation*: set a session cookie prior to login in lab and see whether the same session is kept post-login.
* *Password spraying demo (lab)*: demonstrate why rate limits and lockouts stop mass attempts.

**Testing commands / tactics**

* Inspect cookies and login flows with browser dev tools or Burp.
* Attempt token reuse and check for rotation.

**References**

* OWASP Authentication Cheat Sheet.
* OWASP Session Management Cheat Sheet.

**List of Mapped CWEs**

* CWE-287: Improper Authentication
* CWE-384: Session Fixation
* CWE-613: Insufficient Session Expiration

---

## A08 — Software & Data Integrity Failures

**Factors**

* Trusting third-party updates or plugins without verification.
* Unverified deserialization of user data.
* No signature verification for artifacts.

**Overview**
Problems in software or data integrity allow attackers to run malicious code or tamper with content via the supply chain or insecure deserialization.

**Description**
Examples: plugin systems that accept unsigned plugins, unverified updates, or apps that deserialize user input with unsafe libraries.

**How to Prevent**

* Use signed releases and verify checksums.
* Avoid deserializing untrusted input; if necessary, use safe deserialization libraries and whitelists.
* Sandbox plugin execution and minimize privileges.
* Maintain SBOMs (Software Bill of Materials) and CI verification.

**Example Attack Scenarios (lab-safe)**

* *Unsigned plugin injection (lab)*: local plugin loader accepts arbitrary `.jar` or `.zip` and runs code. Demonstrate how signing prevents this (lab-only).
* *Unsafe deserialization (lab)*: Python `pickle` or Java `readObject()` misuse shown in a controlled VM.

**Testing commands / tactics**

* Review update & plugin flows in app design.
* Static code analysis for deserialization function use.

**References**

* OWASP: Software and Data Integrity Guidelines.
* SLSA & SBOM resources.

**List of Mapped CWEs**

* CWE-494: Download of Code Without Integrity Check
* CWE-502: Deserialization of Untrusted Data
* CWE-346: Origin Validation Error (when applicable)

---

## A09 — Security Logging & Monitoring Failures

**Factors**

* Insufficient logging coverage (missed critical events).
* Logs not centralized, no monitoring/alerting rules.
* Logs not protected from tampering or improper retention.

**Overview**
If you can’t see the attack, you can’t respond. Poor logging and monitoring gives attackers long dwell time.

**Description**
Symptoms: no logs for auth failures, no alerts for privilege escalations, logs deleted by attackers.

**How to Prevent**

* Log authentication events, privilege changes, major configuration changes, and access to sensitive resources.
* Centralize logs (ELK, EFK, Splunk, cloud equivalents) with role-based access.
* Create alerting rules for anomalous activity (mass failed logins, large data exports).
* Ensure logs are immutable or append-only and retained per policy.

**Example Attack Scenarios (lab-safe)**

* *Silent brute force*: simulate repeated failed logins in lab and show absence of alerts. Then enable alerting and demonstrate detection.

**Testing commands / tactics**

* Check event coverage in code and infrastructure; generate events and observe pipeline.
* Validate retention and access controls for log buckets.

**References**

* OWASP Logging Cheat Sheet.
* SANS detection and logging guides.

**List of Mapped CWEs**

* CWE-778: Insufficient Logging & Monitoring (note: CWE mapping may vary)
* CWE-200: Information Exposure (indirect)

---

## A10 — Server-Side Request Forgery (SSRF)

**Factors**

* Server features that fetch remote resources using user-supplied URLs (image previewers, URL-to-PDF, webhooks).
* No validation against private IP ranges or loopback addresses.
* Poor DNS resolution and lack of host / IP filtering.

**Overview**
SSRF allows an attacker to abuse a server’s ability to make HTTP requests, often to reach internal resources not directly exposed to the internet.

**Description**
Examples: a URL preview endpoint that fetches `http://internal-db:5984/_all_docs` after a user submits a URL; attacker uses it to read internal services.

**How to Prevent**

* Implement whitelisting of allowed domains; prefer allowlists over blocklists.
* On outbound requests, perform DNS & IP resolution and block RFC1918 / link-local / metadata IPs.
* Use dedicated outbound proxy with filtering and strict egress rules.
* Apply timeouts, size limits, and response sanitization.

**Example Attack Scenarios (lab-safe)**

* *Local metadata access (lab)*: use lab service simulating cloud metadata on `127.0.0.1:8080` and show how unvalidated URL fetcher returns metadata (lab-only).
* *Open redirect chaining* to SSRF endpoint — show pattern in controlled environment.

**Testing commands / tactics**

* Burp Repeater: send requests containing `http://127.0.0.1:8080/` or `http://[::1]/` to see if server fetches.
* Use DNS-based detection methods (collaborator) to observe outbound callbacks.

**References**

* OWASP SSRF guidance.
* PortSwigger SSRF labs.

**List of Mapped CWEs**

* CWE-918: Server-Side Request Forgery (SSRF)
* CWE-200: Information Exposure (if SSRF leads to data leak)
* CWE-829: Inclusion of Functionality from Unknown Source (if plugin fetcher involved)

---

# Practical testing commands & lab checklist (quick)

> Run these only on lab targets.

* `nmap -sC -sV -oA labscan 127.0.0.1` — service discovery on local lab VM.
* `gobuster dir -u http://localhost:3000 -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50` — directory discovery.
* `sqlmap -u "http://localhost:3000/item?id=1" --batch --dbs` — SQLi testing (lab).
* Burp: Repeater/Intruder + Collaborator for OAST testing.
* `npm audit` / `pip-audit` / `docker scan` for dependency vulnerabilities.
* `linpeas.sh` for Linux privilege discovery (lab-only).
* Record screenshots & sanitized logs for writeups; avoid storing raw credentials.

---

# Semgrep starter rules (copy into `.semgrep.yml` or your CI)

```yaml
rules:
  - id: js-innerhtml-assignment
    message: "Assignment to innerHTML — ensure value is properly encoded/escaped."
    languages: [javascript]
    severity: WARNING
    patterns:
      - pattern: $EL.innerHTML = $VALUE
      - pattern: $EL.insertAdjacentHTML(..., $VALUE)

  - id: node-unsafe-eval
    message: "Use of eval() detected; avoid eval on user-controlled data."
    languages: [javascript]
    severity: ERROR
    pattern: eval($X)

  - id: python-pickle-load
    message: "Use of pickle.load on untrusted data is unsafe."
    languages: [python]
    severity: ERROR
    pattern: pickle.load($X)

  - id: possible-sqli-concat
    message: "Possible SQL string concatenation — check use of parameterized queries."
    languages: [javascript, python]
    severity: WARNING
    pattern-either:
      - pattern: "db.query($SQL + $USER_INPUT)"
      - pattern: "connection.execute($SQL + $USER_INPUT)"
```

Run `semgrep --config=.semgrep.yml` locally and put it into CI.

---

# One-page cheat sheet 

* **Always** validate & authorize server-side.
* Parameterize DB queries; never concatenate user data into queries.
* Use TLS, HSTS, secure cookie flags.
* Rotate session IDs on login/privilege changes.
* Enable MFA for admin workflows.
* Keep dependencies up-to-date; automate vulnerability scans.
* Whitelist domains for outbound fetchers; block private IPs.
* Centralize logs and create alerts for auth failures and large data exports.
* Use signed artifacts and verify integrity for updates/plugins.
* Add Semgrep/Static checks in CI to catch risky patterns early.

---

# Example “sanitized report block” 

**Finding:** Reflected XSS in `/search` (low-medium severity)
**Impact:** An attacker could craft a link that executes JavaScript in victim browsers; exfiltration of session tokens or performing actions on their behalf is possible.
**Repro (lab-only):** Submit `"><script>alert(1)</script>` to the search box on the local Juice Shop instance; the payload is reflected.
**Remediation:** Ensure output encoding on server render paths; avoid `innerHTML` assignments with raw user input; add CSP as defense-in-depth.
**CWE(s):** CWE-79

---

# References & further reading

* OWASP Top 10: [https://owasp.org/Top10/](https://owasp.org/Top10/)
* OWASP Cheat Sheets Collection: [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/)
* PortSwigger Web Security Academy: [https://portswigger.net/web-security](https://portswigger.net/web-security)
* GTFOBins: [https://gtfobins.github.io/](https://gtfobins.github.io/) (privilege escalation patterns)
* Semgrep docs: [https://semgrep.dev/docs/](https://semgrep.dev/docs/)

---

# Commit & PR suggestion 

```bash
git checkout -b docs/owasp-top10-detailed
mkdir -p security
# create file security/owasp-top10.md and paste this entire content
git add security/owasp-top10.md
git commit -m "docs(security): add detailed OWASP Top 10 reference (factors, prevention, PoCs, CWE mapping)"
git push --set-upstream origin docs/owasp-top10-detailed
# PR title:
# docs(security): add detailed OWASP Top 10 reference (factors, prevention, PoCs, CWE mapping)
```

---


