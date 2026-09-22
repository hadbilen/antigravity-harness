---
name: security-review
description: "Comprehensive security review, vulnerability checklist, and verification engine. Invoke when: adding authentication, authorization checks, handling user input, secrets, API endpoints, payment logic, or when user invokes '/security-review', 'security check', 'audit security'."
license: MIT
metadata:
  origin: ECC
---

# Security Review Skill

This skill enforces zero-trust security checks, defense-in-depth principles, and verifiable security boundaries.

## When to Activate

- Implementing authentication or authorization
- Handling untrusted user input or file uploads
- Creating or modifying API endpoints
- Handling credentials, API keys, or secrets
- Implementing financial/payment transactions
- Storing or transmitting sensitive data

## Context Hygiene & Think in Code

* **Computational Scanning:** When scanning for secrets, authorization boundaries, or injection vectors, do not pull source files one by one into conversation context. Execute targeted shell one-liners (`run_command` via ripgrep, Python, find) to extract only suspect lines.
* **Secret Protection:** Never emit `.env` files, SSH keys, or API tokens into command stdout or chat output.

## Subagent Orchestration

For critical security audits, authentication/authorization overhauls, or multi-tenant data boundaries, dispatch the `security-boundary-verifier` subagent via `invoke_subagent` to avoid polluting the main conversation context. The subagent executes negative boundary tests and returns verified evidence to the primary session.

---

## Security Verification Checklists

### 1. Secrets & Credentials Management
- [ ] No hardcoded API keys, secrets, private keys, or tokens in source code or git history.
- [ ] All credentials loaded strictly via environment variables or secret vaults.
- [ ] `.env*` files explicitly listed in `.gitignore`.
- [ ] Secret leaks scanned via computational check that reports LOCATIONS only, never values: `git grep -n -I -E -i "(api_key|secret|private_key|token)[[:space:]]*[:=]" | cut -d: -f1,2`.

### 2. Input Validation & Boundaries
- [ ] All inputs validated at system boundaries with strict typed schemas (e.g. Zod, Pydantic, Joi).
- [ ] Whitelist validation enforced over blacklists.
- [ ] File uploads validate magic bytes / MIME types, file extensions, and strict size caps.
- [ ] Path traversal prevented: reject `..`, unnormalized paths, or use `path.basename` / safe path resolution.

### 3. Injection Prevention (SQL / Command / Template)
- [ ] All SQL queries parameterized or executed through safe query builders/ORMs; zero raw string interpolation.
- [ ] Shell execution (`exec`, `spawn`, `subprocess`) uses argument arrays without `shell=True` / shell expansion.
- [ ] HTML sanitization enforced for user-provided markup (DOMPurify with restricted allowed tags/attributes).
- [ ] React / Vue default escaping preserved; avoid `dangerouslySetInnerHTML` or `v-html` unless strictly sanitized.

### 4. Authentication & Authorization
- [ ] Authentication tokens stored in `httpOnly`, `Secure`, `SameSite=Strict` cookies (avoid vulnerable `localStorage`).
- [ ] Authorization / permission checks performed on every private endpoint and server action; do not rely on client-side routing guards.
- [ ] Row Level Security (RLS) enabled on all multi-tenant database tables with strict user ownership policies.
- [ ] Passwords hashed using Argon2id or bcrypt with appropriate cost factors.

### 5. Transport & Header Security (CSP & CSRF)
- [ ] Content Security Policy (CSP) configured without `'unsafe-inline'` or `'unsafe-eval'`.
- [ ] State-changing requests (POST/PUT/DELETE) protected by CSRF tokens or SameSite strict cookies.
- [ ] Security headers active: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`.

### 6. Rate Limiting & DoS Protection
- [ ] Rate limiting active on authentication endpoints (login, register, password reset) and public APIs.
- [ ] Expensive endpoints (search, report generation, AI completion) protected by stricter per-user/IP caps.
- [ ] Payload size limits configured on incoming JSON/multipart requests.

### 7. Information Leakage & Error Handling
- [ ] User-facing error responses generic; stack traces, internal paths, and db errors logged strictly server-side.
- [ ] Logging utilities redact sensitive fields (`password`, `token`, `cardNumber`, `cvv`, `ssn`).

### 8. Dependency & Supply-Chain Security
- [ ] Dynamic execution tags (`@latest`, unpinned dependencies) forbidden.
- [ ] Lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`) committed and verified.
- [ ] Vulnerability audit run via computational gate: `npm audit` or `pip-audit`.

---

## Pre-Deployment Verification Gate

1. **Static Secret Scan:** Run `git diff origin/main --name-only -G "(key|secret|token|password)[[:space:]]*[:=]"` to list files that add secret-like assignments (file names only; inspect them without echoing values).
2. **Cloud & Infrastructure:** For deployments, IAM, logging/monitoring or CI/CD changes, also apply the checklist in `references/cloud-infrastructure-security.md`.
3. **Endpoint Auth Audit:** Verify every exported route / controller implements explicit auth guard.
4. **Automated Security Tests:** Run integration tests verifying unauthorized access returns 401/403.
