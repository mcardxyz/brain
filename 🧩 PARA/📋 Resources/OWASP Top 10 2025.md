___

# OWASP Top 10 2025

## A01: Broken Access Control
- When the server doesn’t properly enforce **who can access what** on every request.
- A common occurence of this is **IDOR** (Insecure Direct Object Reference)
	- For e.g. changing an ID - like `?id=7` → `?id=6` let’s you see or edit someone else’s data


## AS02: Security Misconfigurations
- When systems, servers, or applications are deployed with unsafe defaults, incomplete settings, or exposed services


## AS03: Software Supply Chain Failures
- When applications rely on components, libraries, services, or models that are compromised, outdated, or improperly verified.
- **How to protect:**
	- Verify all third-party components, libraries, and AI models before use
	- Monitor and patch dependencies regularly
	- Sign, verify, and audit software updates and packages
	- Lock down CI/CD pipelines and build processes to prevent tampering, etc.


## AS04: Cryptographic Failures
- When encryption is used incorrectly or not at all. This includes weak algorithms, hard-coded keys, poor key handling, or unencrypted sensitive data.


## AS06: Insecure Design
- When flawed logic or architecture is built into a system from the start. These flaws stem from skipped threat modelling, no design requirements or reviews, or accidental errors.


## A07: Authentication Failures
- When an application can’t reliably verify or bind a user’s identity
	- Username enumeration
	- Weak/guessable password
	- Logic flaws in the login/registration flow
	- Insecure session or cookie handling
- This allows an attacker to log in as someone else or bind a session to the wrong account


## A09: Logging & Alerting 
- When applications don’t record or alert on security events
