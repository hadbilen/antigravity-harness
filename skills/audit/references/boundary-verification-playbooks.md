# Security Boundary & Negative Verification Playbooks

This document details the six core verification vectors used to audit boundary security across software architectures, protocols, and data contracts. It provides mechanisms of failure and required **Negative Test Case** templates demanded during `/audit --boundary` (or `/audit --resilience`) inspections.

---

## 1. Object-Level Access Boundary Verification (IDOR / Broken Access Control)

### Mechanism of Failure
Even when a client is authenticated server-side, the system fails to verify that the requested object (record, order, profile, document) belongs to the requesting identity. Client-supplied IDs (`id`, `uuid`, `tenant_id`) are trusted blindly.

### Verification Vectors
* Sequential or predictable identifiers (`/api/orders/1001` -> `/api/orders/1002`).
* Horizontal Privilege Escalation: User A accesses or modifies data belonging to User B.
* Vertical Privilege Escalation: Standard authenticated users invoking administrative endpoints (`/api/admin/users/1`).
* Parameter Confusion: Valid user in URL parameter, while JSON payload references an unauthorized target identity (`{"ownerId": "other_user"}`).

### Mandatory Negative Test Case Template
```http
POST /api/documents/delete HTTP/1.1
Host: local-service
Authorization: Bearer <User_A_Token>
Content-Type: application/json

{"document_id": "doc_owned_by_User_B"}

--> Expected Secure Response: 403 Forbidden
--> Defective / Vulnerable Response: 200 OK {"status": "deleted"}
```

---

## 2. Network Boundaries & External Request Isolation (SSRF & Metadata Probing)

### Mechanism of Failure
The application accepts a URL, webhook endpoint, or remote resource link from user input and initiates a server-side HTTP/TCP request without filtering internal loopback addresses, cloud metadata services, or restricted IP ranges.

### Verification Vectors
* Cloud Metadata Endpoints: Probing `http://169.254.169.254/latest/meta-data/` or cloud provider internal APIs.
* Internal Network Probing: Directing traffic to `http://127.0.0.1:8080/admin`, `http://10.0.0.5:6379` (Redis), or internal microservices.
* Protocol Leakage: Processing schemes like `file:///` or `gopher://`.
* Filter Bypasses: Using `0.0.0.0`, `127.1`, `http://[::]:80/`, or DNS rebinding to evade regex filters.

### Mandatory Negative Test Case Template
```json
// POST /api/integrations/webhook
{
  "target_url": "http://169.254.169.254/latest/meta-data/"
}
// Expected Secure Behavior: Pre-flight blocked at network layer, returns 400 Bad Request.
// Defective Behavior: Internal instance metadata echoed in response body.
```

---

## 3. Concurrency & State Invariants (Race Conditions / TOCTOU)

### Mechanism of Failure
State is not preserved atomically across the Time-of-Check to Time-of-Use (TOCTOU) window. A balance check succeeds, but before the decrement completes, a concurrent operation executes without mutex or database row locking.

### Verification Vectors
* Parallel Requests: Replaying identical coupons, balance transfers, or ticket reservations within millisecond windows.
* Negative Balance / Inventory Drift: Two concurrent withdrawals of 90 units against an account balance of 100 units both succeed.
* Shared Resource Collision: Reading a resource that is concurrently updated without optimistic locking or version checks.

### Mandatory Negative Test Case Template
```python
# Concurrency Boundary Test
import asyncio, httpx

async def send_transfer(client):
    return await client.post("/api/wallet/withdraw", json={"amount": 90})

async def test_race_condition():
    async with httpx.AsyncClient() as client:
        # Balance is 100 units; dispatch two concurrent requests:
        res1, res2 = await asyncio.gather(send_transfer(client), send_transfer(client))
        # Expected Secure Behavior: One request returns 200 OK; the other returns 400/409 (Insufficient Funds).
        # Defective Behavior: Both requests return 200 OK and balance falls below zero.
```

---

## 4. Input Parsing & Injection Boundaries

### Mechanism of Failure
User input is interpolated directly into SQL statements, shell execution arguments, or template engines via string concatenation rather than parameterized queries or safe parsing boundaries.

### Verification Vectors
* Database Query Boundaries: Quotes, comments, and logical operators in unparameterized ORM/SQL queries.
* Command Execution: Shell argument separators (`;`, `&&`, `|`) passed to `exec()` or `spawn()`.
* Template Injection: User strings evaluated as executable expressions (`{{7*7}}`).

### Mandatory Negative Test Case Template
```http
// Parameterized Query Verification Test
GET /api/products?category=electronics'-- HTTP/1.1

--> Expected Secure Response: 400 Bad Request or literal text match for "electronics'--" (0 results).
--> Defective Response: 500 SQL Syntax Error or unconstrained table dump.
```

---

## 5. Token & Session Integrity

### Mechanism of Failure
Lax signature verification on JWTs/tokens, predictable secret keys, failure to validate expiration timestamps (`exp`), or lack of server-side session revocation.

### Verification Vectors
* Unsigned Token Acceptance: Sending `alg: "none"` accepted without signature check.
* Key Confusion: Systems expecting asymmetric keys accepting symmetric HMAC tokens signed with the public key.
* Expired Tokens: Honoring tokens past their `exp` window or retaining sessions after password resets.

### Mandatory Negative Test Case Template
```json
// Token Integrity Test (alg: "none" scenario)
// Header:
{"alg": "none", "typ": "JWT"}
// Payload:
{"user_id": "target_user", "role": "admin"}
// Sent unsigned:
// Expected Secure Response: 401 Unauthorized (Invalid Signature).
// Defective Response: 200 OK.
```

---

## 6. Insecure Deserialization & File Handling

### Mechanism of Failure
Deserializing untrusted client payloads (Python `pickle`, PHP `unserialize`, YAML `unsafe_load`) without type constraints, or permitting unsanitized file paths in upload endpoints.

### Verification Vectors
* Arbitrary Class Instantiation: Triggering dangerous object initialization via untrusted byte streams.
* Path Traversal: Unsanitized `../../` sequences writing files outside intended upload directories.
* Extension & MIME Confusion: Relying solely on client `Content-Type` header without verifying file magic bytes.

### Mandatory Negative Test Case Template
```http
POST /api/user/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary123

------Boundary123
Content-Disposition: form-data; name="file"; filename="../../config/override.json"
Content-Type: application/json

{"role": "admin"}
------Boundary123--

--> Expected Secure Response: 400 Bad Request (Invalid filename / Path traversal blocked).
--> Defective Response: File written to parent configuration directory with 200 OK.
```
