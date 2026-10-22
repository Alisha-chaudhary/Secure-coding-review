# Detailed Findings - IdentityGuard Secure Coding Review

Each finding includes the vulnerable code (from the real IdentityGuard repository), why it is unsafe, severity, CWE mapping, and remediation direction.

---

## SC-01 - No Rate Limiting on Login Endpoint

**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)  
**Severity:** High  
**Location:** `app/auth/routes.py`, function `login()`

### Vulnerable Code
```python
@router.post("/login", response_model=LoginResponse)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    try:
        token = authenticate(db, request.username, request.password)
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    return LoginResponse(access_token=token)
```

### Why It Is Unsafe
The login endpoint has no rate limiting, account lockout after N failures, or CAPTCHA. An attacker can perform unlimited credential-stuffing or brute-force attacks against usernames. 
Although the project uses generic error messages ("Invalid credentials") to prevent user enumeration, unlimited attempts still allow password guessing.

### Exploitability
Remote, no authentication required. Automated tools can submit thousands of login attempts per hour.

### Remediation Direction
Add rate limiting (e.g., via FastAPI middleware, `slowapi`, or Redis-backed request counters) and enforce account lockout after repeated failures. See [`audit/remediation.md`](remediation.md).

---

## SC-02 — No Server-Side JWT Revocation / Denylist

**CWE:** CWE-613 (Insufficient Session Expiration)  
**Severity:** High  
**Location:** `app/auth/routes.py`, `app/main.py`

### Why It Is Unsafe
The project's README documents this limitation: *"logout is client-side; no server-side token denylist."* JWTs are short-lived, but once issued they remain valid until expiration. 
If a token is stolen or a user is terminated, there is no way to invalidate it server-side before expiry. The client can delete the token, but the server still honors it.

### Exploitability
Requires token theft or a compromised session. An attacker with a stolen JWT can impersonate the user until the token expires.

### Remediation Direction
Implement a server-side token denylist (Redis-backed blocklist of JTI claims) checked on each authenticated request, or reduce JWT expiry and issue refresh tokens with rotation.

---

## SC-03 — Silent Exception Swallowing in PAM Expiry Sweeper

**CWE:** CWE-703 (Improper Check or Handling of Exceptional Conditions)  
**Severity:** Medium  
**Location:** `app/main.py`, function `_pam_expiry_loop()`

### Vulnerable Code
```python
async def _pam_expiry_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(_sweep_expired_checkouts)
        except Exception:  # never let the sweeper die
            logger.exception("PAM expiry sweep failed")
        await asyncio.sleep(PAM_EXPIRY_SWEEP_SECONDS)
```

### Why It Is Unsafe
The bare `except Exception` catches and logs every error but continues silently. If the PAM expiry sweep fails due to a database connection issue, schema mismatch, or permission error, the system keeps running but overdue checkouts are never expired. 
Privileged access may remain active beyond its intended duration. Operators are alerted only via logs, not via alerts or failed health checks.

### Exploitability
Indirect. An attacker who can cause database instability may prevent privilege expiration, extending their window of privileged access.

### Remediation Direction
Catch specific exceptions only, surface sweep failures through the `/health` endpoint or monitoring, and alert on repeated failures rather than swallowing them silently.

---

## SC-04 — Bare `except Exception` Fallback Masks Policy-Engine Failures

**CWE:** CWE-703  
**Severity:** Medium  
**Location:** `app/iam/access_requests.py`, function `_require_privileged_authority()`

### Vulnerable Code
```python
if POLICY_AUTHZ_ENABLED and target_user is not None:
    try:
        from app.authz.policy_service import can_assign_role_with_policy
        if not can_assign_role_with_policy(db, actor, target_user, role):
            ...
            raise PrivilegedRoleAuthorizationError(reason)
        return
    except Exception:
        # Fallback keeps the legacy permission check authoritative.
        pass
```

### Why It Is Unsafe
If the policy engine throws an exception (import error, malformed policy JSON, database query failure), the `except Exception: pass` silently falls back to the legacy permission check. Operators may believe policy-based authorization is active when it has silently degraded to the legacy path. This creates a false sense of security and makes policy failures invisible.

### Exploitability
Indirect. A malformed policy file could silently disable the newer policy engine without alerting administrators.

### Remediation Direction
Log policy-engine failures at WARNING or ERROR level, emit a metric/alert, and consider failing closed (denying privileged assignment) when the policy engine is enabled but unavailable.

---

## SC-05 — No Password Reuse / History Prevention

**CWE:** CWE-521 (Weak Password Requirements)  
**Severity:** Medium  
**Location:** `app/auth/routes.py`, function `change_password()`

### Vulnerable Code
```python
if verify_password(request.new_password, current_user.password_hash or ""):
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="New password must differ from the current password",
    )
```

### Why It Is Unsafe
The change-password endpoint only ensures the new password differs from the current one. It does not check against a password history, so a user can alternate between two passwords (e.g., `Password1` → `Password2` → `Password1`). Weak password strength is enforced via `check_password_strength`, but reuse is not prevented.

### Exploitability
Requires authenticated access to a user's account. Low direct impact, but weakens credential hygiene.

### Remediation Direction
Maintain a password history table (last N password hashes) and reject new passwords that match any historical hash.

---

## SC-06 — SQLite Without Migration Framework

**CWE:** CWE-1036 (Exposure of Resources to Wrong Sphere) — related to schema/evolution risk  
**Severity:** Low  
**Location:** `app/main.py`, project README (`Current limitations`)

### Why It Is Unsafe
The project uses SQLite without Alembic or another migration framework. The README states: *"Storage and schema changes: SQLite without a migration framework."* Schema changes require manual SQL or table recreation, risking data loss or inconsistent schema across environments. There is no versioned migration history.

### Exploitability
Low. Primarily an operational/resilience concern, not directly exploitable by external attackers.

### Remediation Direction
Add Alembic (or SQLAlchemy migrations) with versioned migration scripts and test migrations against a copy of production data before applying.

---

## SC-07 — Detailed User Information Exposed on `/auth/me`

**CWE:** CWE-200 (Information Exposure)  
**Severity:** Low  
**Location:** `app/auth/routes.py`, function `get_me()`

### Vulnerable Code
```python
@router.get("/me")
def get_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    ...
    return {
        "username": current_user.username,
        "full_name": current_user.full_name,
        "employee_id": current_user.employee_id,
        "department_id": current_user.department_id,
        "status": current_user.status,
        "roles": active_roles,
        "permissions": sorted(get_active_permissions(db, current_user)),
    }
```

### Why It Is Unsafe
The `/auth/me` endpoint returns personally identifying information (full name, employee ID, department ID) plus the user's full roles and permissions. While the endpoint is authenticated, this data could aid an attacker who compromises a low-privilege account in planning further privilege escalation or social engineering.

### Exploitability
Requires a valid authenticated session. Low impact on its own, but increases the blast radius of session compromise.

### Remediation Direction
Return only the fields needed by the client (e.g., username and roles). Consider field-level visibility controls or a separate `/auth/me/summary` endpoint with minimal data.

---

## 8. Strengths Observed

The following controls were implemented well and should be maintained:

| Control | Evidence |
|---------|----------|
| Password hashing | Argon2id via `argon2-cffi` |
| Generic login errors | `"Invalid credentials"` prevents user enumeration |
| Login lockout / password policy | Documented in README; enforced in `app/auth/service.py` |
| Short-lived JWT sessions | `PyJWT` with expiry |
| Backend-enforced RBAC | `require_permission()` dependency on all routes |
| Self-approval prevention | `SelfApprovalError` in `approve_access_request()` |
| Four-eyes provisioning | Approver ≠ provisioner for privileged roles |
| SoD checks | `evaluate_user_sod()` in `app/governance/sod.py` |
| Tamper-evident audit trail | Hash-chained events in `app/audit/` |
| Policy engine | PBAC/ABAC engine in `app/authz/policy_engine.py` |
