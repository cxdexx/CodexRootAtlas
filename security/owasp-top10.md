# OWASP Top 10 (2021) — Quick Dev Notes

_This is a compact, practical developer/engineer reference to the OWASP Top 10 (2021)._
Keep this short and useful — include links to full OWASP pages in your browser for deeper reading.

---

Table of contents
1. [A01: Broken Access Control](a01-broken-access-control)  
2. [A02: Cryptographic Failures](a02-cryptographic-failures)  
3. [A03: Injection](a03-injection)  
4. [A04: Insecure Design](a04-insecure-design)  
5. [A05: Security Misconfiguration](a05-security-misconfiguration)  
6. [A06: Vulnerable and Outdated Components](a06-vulnerable-and-outdated-components)  
7. [A07: Identification & Authentication Failures](a07-identification--authentication-failures)  
8. [A08: Software and Data Integrity Failures](a08-software-and-data-integrity-failures)  
9. [A09: Security Logging & Monitoring Failures](a09-security-logging--monitoring-failures)  
10. [A10: Server-Side Request Forgery (SSRF)](a10-server-side-request-forgery-ssrf)

---

## How to use this file
- Use this as the elevator pitch for a finding in a report.
- For each item: short description → quick real-world example (lab-safe) → minimal remediation checklist → one-line test or detection method.
- Keep PoC details lab-only (Docker / Juice Shop / DVWA) and never publish raw exploit steps for real targets.

---

### A01: Broken Access Control
**Description:** Missing or faulty checks that allow users to perform actions they shouldn't (e.g., horizontal/vertical privilege escalation).

**Lab-safe example:** Changing `/user/123/profile` to `/user/122/profile` and seeing another user's data.

**Quick detection:** Try manipulating IDs, HTTP verbs, query params; use Burp Repeater and check for 200 responses on unauthorized resources.

**Mitigation checklist**
- Enforce authorization server-side on every endpoint (deny-by-default).
- Use role-based access controls and attribute-based checks.
- Don’t trust client-side controls (e.g., hidden form fields).
- Use incremental object-level authorization checks (resource owner vs. requestor).

**Code hint (Node/Express middleware):**

...................................................................................

js

// pseudo-middleware

function requireOwnerOrRole(req, res, next) {

  if (req.user.id === req.params.id || req.user.role === 'admin') return next();
  
  return res.status(403).send('forbidden');
}

..................................................................................

## A02: Cryptographic Failures
**Description:** Weak or missing cryptography causing sensitive-data exposure.

**Lab-safe example:** Passwords stored in plaintext in a local DB.

**Quick detection:** Inspect storage and transport: are passwords hashed? Is TLS enforced? Check cookie flags.

Mitigation checklist

Use TLS everywhere (HSTS, redirect HTTP→HTTPS).

Store passwords with a strong KDF (bcrypt/argon2/scrypt).

Sign and validate tokens (use robust libs, avoid homegrown crypto).

Set cookies with Secure; HttpOnly; SameSite=Strict where appropriate.

Password example (bcrypt):

..................................................................................

js
const bcrypt = require('bcrypt');

const hash = await bcrypt.hash(password, 12); // store hash

CSP & secure cookies (example header):

...................................................................................

vbnet

Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict

Content-Security-Policy: default-src 'self'

...................................................................................


## A03: Injection
**Description:** User-supplied data interpreted as code or a command (SQL, OS, LDAP, NoSQL, etc.)

Lab-safe example:** ' OR '1'='1 against a lab SQL endpoint.

**Quick detection:** Fuzz inputs, use Burp intruder, and test with sqlmap on lab targets only.

Mitigation checklist

Use parameterized queries / prepared statements or ORM.

Validate & sanitize input but rely primarily on proper query APIs.

Apply least privilege to DB accounts.

Node + parameterized query (pg):

...................................................................................

js

const res = await db.query('SELECT * FROM users WHERE id = $1', [userId]);

...................................................................................


## A04: Insecure Design
**Description:** Missing or weak security design — architectural problems, not single bugs.

**Lab-safe example:** No rate limits on authentication endpoints or missing threat modeling.

Quick detection: Review design docs, sequence diagrams; check for missing controls (rate limit, MFA, input validation).

Mitigation checklist

Perform threat modeling (e.g., STRIDE) early.

Establish secure design patterns (defense-in-depth).

Bake in fail-safe defaults and explicit security requirements.

## A05: Security Misconfiguration
**Description:** Default configs, verbose errors, open admin panels, unnecessary services.

**Lab-safe example:** Debug endpoints enabled on a dev build exposing stack traces.

**Quick detection:** Run a config checklist:

Exposed .env files?

Default credentials?

Directory listings?

Unnecessary ports open?

Mitigation checklist

Harden servers and containers; remove dev endpoints from prod.

Use secure defaults and automated configuration management.

Scan with tools like nikto, sslscan, or local config scanners.

## A06: Vulnerable & Outdated Components
**Description:** Using libraries or components with known CVEs.

**Lab-safe example:** Local app using an old vulnerable npm package in a Docker build.

**Quick detection:** Use npm audit, pip-audit, Dependabot/Snyk or oss-review-toolkit in CI.

Mitigation checklist

Keep dependencies updated; subscribe to CVE feeds.

Use dependency scanners in CI (Dependabot, Snyk, GitHub alerts).

Limit runtime permissions and use isolation (containers with minimal images).

## A07: Identification & Authentication Failures
**Description:** Weak or broken authentication, session management problems.

**Lab-safe example:** Session IDs in URLs or predictable token generation in a lab server.

**Quick detection:** Check login flows, session rotation on privilege change, timeouts, MFA presence.

Mitigation checklist

Use secure session storage; rotate session IDs after login and privilege changes.

Implement MFA for sensitive actions.

Enforce strong password policies and account lockouts/rate-limiting.

## A08: Software & Data Integrity Failures
**Description:** Unsigned/unaltered software, or untrusted deserialization leading to code execution.

**Lab-safe example:** Accepting uploaded plugins without verifying signature (lab-only demo).

**Quick detection:** Identify update and import mechanisms; look for deserialization of untrusted data.

Mitigation checklist

Use signed releases, checksums, and reproducible builds.

Avoid insecure deserialization; if needed, whitelist classes and validate payloads.

Isolate plugin systems and run with least privileges.

## A09: Security Logging & Monitoring Failures
**Description:** Insufficient logging, monitoring, or alerting — attackers may be present longer.

**Lab-safe example:** No alerts for repeated failed logins in a local test app.

**Quick detection:** Check retention, log coverage, and if alerts trigger on suspicious events.

Mitigation checklist

Centralize logs (ELK/EFK/Cloud) and instrument critical events (authn, authz, config changes).

Create alerts for brute force, privilege changes, and data exfil pattern.

Ensure logs are tamper-evident and access-controlled.

Minimal events to log: auth success/fail, privilege changes, new admin creation, mass downloads.

## A10: Server-Side Request Forgery (SSRF)
**Description:** Attacker tricks the server into making requests that reach internal systems.

**Lab-safe example:** App fetches a user-submitted URL and returns results — attacker points it at http://127.0.0.1:8080/admin.

**Quick detection:** Review endpoints that fetch remote resources (image fetchers, URL previews). Use Burp to send internal IPs.

Mitigation checklist

Block private IP ranges when making outbound requests (whitelist only).

Validate and normalize user-supplied URLs; use a safe HTTP client with timeouts.

Enforce network segmentation for internal services.


