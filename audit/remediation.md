# Remediation & Secure Coding Best Practices - IdentityGuard

Secure code fixes for each finding in the IdentityGuard secure coding review, plus general best-practice recommendations.

---

## SC-01 Fix - Add Rate Limiting to Login

### Approach
Use `slowapi` (or Redis-backed counters) to limit login attempts per IP and per username.

### Example
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")  # 5 attempts per minute per IP
def login(request: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    ...
```

Add account lockout after N failed attempts (store `failed_login_count` and `locked_until` on the `User` model).

---

## SC-02 Fix - Server-Side JWT Denylist

### Approach
Store the JWT JTI (unique token ID) in a Redis blocklist on logout or user termination. Check the blocklist on each authenticated request via a FastAPI dependency.

### Example
```python
import redis
from jose import jwt

redis_client = redis.Redis(host="localhost", port=6379, db=0)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    jti = payload.get("jti")
    if redis_client.get(f"blocklist:{jti}"):
        raise HTTPException(status_code=401, detail="Token revoked")
    ...
```

On logout: `redis_client.setex(f"blocklist:{jti}", ttl_expiry, "revoked")`.

---

## SC-03 Fix - Handle PAM Sweeper Exceptions Explicitly

### Approach
Catch only expected exceptions, surface failures through `/health`, and alert on repeated failures.

### Example
```python
from fastapi import FastAPI

pam_sweep_last_error: str | None = None
pam_sweep_failure_count = 0

async def _pam_expiry_loop() -> None:
    global pam_sweep_last_error, pam_sweep_failure_count
    while True:
        try:
            await asyncio.to_thread(_sweep_expired_checkouts)
            pam_sweep_last_error = None
            pam_sweep_failure_count = 0
        except (OperationalError, ProgrammingError) as exc:
            pam_sweep_last_error = str(exc)
            pam_sweep_failure_count += 1
            logger.exception("PAM expiry sweep failed")
        await asyncio.sleep(PAM_EXPIRY_SWEEP_SECONDS)

@app.get("/health")
def health():
    status = "ok" if pam_sweep_failure_count == 0 else "degraded"
    return {"status": status, "service": "identityguard", "pam_sweep_error": pam_sweep_last_error}
```

---

## SC-04 Fix - Fail Visibly When Policy Engine Fails

### Approach
Log policy-engine failures and fail closed when `POLICY_AUTHZ_ENABLED` is true.

### Example
```python
import logging

logger = logging.getLogger("identityguard.policy")

if POLICY_AUTHZ_ENABLED and target_user is not None:
    try:
        from app.authz.policy_service import can_assign_role_with_policy
        if not can_assign_role_with_policy(db, actor, target_user, role):
            ...
            raise PrivilegedRoleAuthorizationError(reason)
        return
    except Exception as exc:
        logger.error("Policy engine failed, falling back to legacy check", exc_info=True)
        # Optional: fail closed instead of silent fallback
        # raise PrivilegedRoleAuthorizationError("Policy engine unavailable")
```

---

## SC-05 Fix - Password History Prevention

### Approach
Store previous password hashes in a `password_history` table and reject matches.

### Example
```python
class PasswordHistory(Base):
    __tablename__ = "password_history"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=now)

# In change_password():
recent_hashes = db.query(PasswordHistory.password_hash).filter_by(user_id=current_user.id).limit(5).all()
if any(verify_password(request.new_password, h[0]) for h in recent_hashes):
    raise HTTPException(422, "Password has been used before. Choose a different one.")
```

---

## SC-06 Fix - Add Database Migrations

### Approach
Add Alembic for versioned schema migrations.

### Example
```powershell
pip install alembic
alembic init alembic
# Edit alembic.ini with your SQLAlchemy URL
# Generate migrations: alembic revision --autogenerate -m "description"
# Apply: alembic upgrade head
```

Store migration files in version history and test against a staging copy of production data.

---

## SC-07 Fix - Minimize `/auth/me` Response

### Approach
Return only fields the frontend actually needs.

### Example
```python
@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)) -> dict:
    return {
        "username": current_user.username,
        "roles": active_roles,
    }
```

Move sensitive fields (employee_id, department_id) behind a separate endpoint with stricter authorization.

---

## General Secure Coding Recommendations

| Category | Recommendation |
|----------|----------------|
| **Rate limiting** | Apply to all authentication endpoints (`/login`, `/change-password`) |
| **Session security** | Short JWT expiry + refresh token rotation + server-side revocation |
| **Error handling** | Never silently swallow exceptions in security-critical paths; log and alert |
| **Secrets management** | Validate `IDENTITYGUARD_JWT_SECRET` strength at startup; never commit secrets |
| **Dependency scanning** | Add `pip-audit` or `safety` to CI/CD |
| **Static analysis** | Run Bandit in CI on every pull request |
| **Security headers** | Add `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` via FastAPI middleware |
| **Audit logging** | Ensure all access-denied events are logged (already done well in IdentityGuard) |

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Bandit documentation](https://bandit.readthedocs.io/)
- [slowapi rate limiting](https://github.com/tylerdowney/slowapi)
- [Alembic database migrations](https://alembic.sqlalchemy.org/)
