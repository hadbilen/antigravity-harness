---
name: security-review
description: "Comprehensive security review, vulnerability checklist, and verification engine. Invoke when: adding authentication, authorization checks, handling user input, secrets, API endpoints, payment logic, or when user invokes '/security-review', 'security check', 'audit security'."
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

## Context Hygiene & Think in Code (Bağlam Hijyeni)

* **Hesaplamalı Tarama:** Gizli anahtar, yetki sınırları veya enjeksiyon açıkları taranırken kaynak dosyaları tek tek bağlama çekmek yasaktır. Terminal üzerinde `grep_search` veya tek satırlık terminal betikleri (ripgrep, Python, find) çalıştırılarak yalnızca ihlal şüphesi taşıyan satırlar getirilir.
* **Gizlilik Koruması:** `.env` dosyaları, SSH anahtarları ve API anahtarları komut satırında veya çıktıda asla ifşa edilmez.

## Subagent Orchestration (Uzman Alt Ajan Delege Protokolü)

Kritik güvenlik denetimlerinde, kimlik doğrulama/yetkilendirme mimarilerinde veya çok kiracılı (multi-tenant) veri sınırlarında ana oturumu kirletmemek için `security-boundary-verifier` alt ajanı (`invoke_subagent`) çağrılır. Alt ajan negatif test senaryolarını çalıştırır ve doğrulanmış kanıtları ana oturuma iletir.

---

## Security Verification Checklists

### 1. Secrets & Credentials Management
- [ ] No hardcoded API keys, secrets, private keys, or tokens in source code or git history.
- [ ] All credentials loaded strictly via environment variables or secret vaults.
- [ ] `.env*` files explicitly listed in `.gitignore`.
- [ ] Secret leaks scanned via computational check: `git grep -E -i "(api_key|secret|private_key|token)[[:space:]]*[:=]"`.

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

1. **Static Secret Scan:** Run `git diff origin/main | grep -iE "(key|secret|token|password)"` to confirm zero leaks.
2. **Endpoint Auth Audit:** Verify every exported route / controller implements explicit auth guard.
3. **Automated Security Tests:** Run integration tests verifying unauthorized access returns 401/403.
