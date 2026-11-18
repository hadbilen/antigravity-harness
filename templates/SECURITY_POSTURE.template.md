# Internal Security Posture & Control Ledger (`SECURITY_POSTURE.md`)

**System / Repository:** `{{project-slug}}`
**Threat Model Scope:** `{{Public multi-tenant HTTP API / Privileged local daemon / Embedded firmware}}`
**Last Audited Commit:** `{{commit-sha}}`

> [!WARNING]
> **Why `SECURITY_POSTURE.md` Exists Separately From `SECURITY.md`:**
> GitHub, GitLab, and Forgejo automatically surface a repository's root `SECURITY.md` file in the public **Security Policy** tab. Recording unverified or missing security controls in `SECURITY.md` publishes an exploit roadmap to external attackers on public or mirrored repositories. Keep root `SECURITY.md` strictly for public vulnerability disclosure contact instructions, and track concrete `[ENFORCED]` vs. `` `[REQUIRED — UNVERIFIED]` `` engineering controls exclusively in `SECURITY_POSTURE.md`.

## 1. Enforced Controls (`[ENFORCED]`)

**Hard Evidentiary Rule:** A control may appear in this `[ENFORCED]` table **only** when both its `Enforcing Code Path` exists on disk and its `Verifying Test Path` executes a discriminating positive + negative boundary check that currently passes (`exit 0`). If either path is missing, unimplemented, or failing, move the row immediately to Section 2 (`` `[REQUIRED — UNVERIFIED]` ``).

| Control ID | Status | Threat / Trust Boundary | Concrete Mechanism, Numeric Limit & Rejection Code | Enforcing Code Path | Verifying Test Path |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-01` | `[ENFORCED]` | {{Untrusted HTTP request body ingress (`POST /api/v1/upload`)}} | {{Rejects bodies exceeding `1_048_576` bytes (`1 MiB`) before heap buffering with HTTP `413 Payload Too Large` and `Content-Type` allowlist mismatch with HTTP `415`}} | `{{src/http/middleware/body_limit.rs}}` | `{{tests/http_bounds.rs::rejects_oversized_and_wrong_mime_payload}}` |
| `SEC-02` | `[ENFORCED]` | {{Password and session token verification}} | {{Hashes passwords with `Argon2id` (`m = 65536 KiB`, `t = 3`, `p = 4`), verifies `Ed25519` JWT signatures with explicit `alg` allowlist (`alg: "none"` rejected with HTTP `401`), and expires access tokens at `900s` (`15m`)}} | `{{src/auth/verify.rs}}` | `{{tests/auth_tokens.rs::rejects_alg_none_and_expired_jwt}}` |
| `SEC-03` | `[ENFORCED]` | {{Cross-tenant object access (`GET /api/v1/orders/:id`)}} | {{Scopes every SQL query by server-verified `tenant_id` bound parameter; cross-tenant IDs return HTTP `404 Not Found` (`0` rows leaked)}} | `{{src/orders/repository.rs}}` | `{{tests/tenant_idor.rs::user_b_cannot_read_or_mutate_user_a_order}}` |

## 2. Required Unverified Controls (`` `[REQUIRED — UNVERIFIED]` ``)

Track every planned, partially implemented, or untested security control here until both code and negative boundary tests pass. Any row marked `Release Blocker = YES` blocks production deployment and fails `/security-review` release sign-off.

| Control ID | Status | Threat / Trust Boundary | Required Mechanism, Numeric Limit & Rejection Code | Missing Evidence (Code / Test) | Tracking ADR / Owner | Release Blocker |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-04` | `` `[REQUIRED — UNVERIFIED]` `` | {{Outbound webhook dispatcher (`POST /api/v1/webhooks/test`)}} | {{Resolve DNS once, pin socket IP, and reject RFC 1918, loopback (`127.0.0.0/8`, `::1`), CGNAT (`100.64.0.0/10`), and link-local metadata (`169.254.0.0/16`, `fe80::/10`) targets with HTTP `422` within a `3_000 ms` deadline}} | {{DNS-pinning dialer implemented in `{{src/net/safe_dial.rs}}`, negative IPv6-mapped loopback test missing}} | `{{docs/adr/0004-webhook-ssrf-pinning.md}}` / `{{@security-owner}}` | `YES` |
| `SEC-05` | `` `[REQUIRED — UNVERIFIED]` `` | {{Local daemon startup privilege drop}} | {{Drop supplementary groups (`setgroups(&[])`), GID (`setresgid`), and UID (`setresuid`) before spawning worker threads; verify `setuid(0)` fails with `EPERM`}} | {{Negative `setuid(0) -> EPERM` integration test unrun in rootless CI container}} | `{{docs/adr/0005-daemon-privdrop.md}}` / `{{@platform-owner}}` | `NO` |

## 3. Authoring & Verification Rules (`audit` Pass 2 & Phase 0.B)

1. **Zero Subjective Adjectives:** Words such as `securely`, `safely`, `fast`, `robust`, `adequate`, `properly`, `strict`, or `industry-standard` are prohibited unless paired on the same line with the exact algorithm, numeric ceiling, timeout, and error code (`audit` Mode 1 Pass 2 Vagueness Filter).
2. **Named Primitives & Exact Parameters:** Specify exact algorithms and parameters (for example `TLS 1.3`, `AEAD ChaCha20-Poly1305`, `Argon2id m=65536,t=3,p=4`, `SHA-256`, `SERIALIZABLE` transaction isolation, `max_body = 1 MiB`, `rate_limit = 60 req/min/IP`, `timeout = 5_000 ms`) and exact rejection codes (`HTTP 401`, `HTTP 403`, `HTTP 413`, `HTTP 429`, `EPERM`, `ENOMEM`, `EINVAL`).
3. **Zero Secret Values (`GEMINI.md` Rule 12):** Never paste keys, tokens, salts, private certificates, or live internal credentials into this file; cite configuration variable names and `file` paths only.
4. **Audit Grounding (`audit` Phase 0.B & `/security-review`):** During `/audit` and `/security-review`, any `[ENFORCED]` row whose cited code path or test path does not exist on disk is reported as a `HIGH` `[FACT]` drift defect, and any `` `[REQUIRED — UNVERIFIED]` `` row with `Release Blocker = YES` blocks release readiness.
