# Secure Coding Review - IdentityGuard 🔍

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-web%20framework-lightgrey)](https://fastapi.tiangolo.com/)
[![Bandit](https://img.shields.io/badge/Static%20Analysis-Bandit-green)](https://bandit.readthedocs.io/)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/www-project-top-ten/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

I performed a secure coding review of [**IdentityGuard**](https://github.com/Alisha-chaudhary/IdentityGuard) - my own FastAPI + SQLAlchemy IAM governance lab. I ran static analysis with Bandit and a manual source-code review, then documented my findings with severity ratings and CWE mappings, and provided remediation steps with secure code examples.

> **Scope:** My own project, audited by me. No third-party, production, or real company systems were accessed. This is educational portfolio work for CodeAlpha.

---

## 🎯 What This Project Does

| Phase | What I Did |
|-------|------------|
| **Target under audit** | I reviewed `https://github.com/Alisha-chaudhary/IdentityGuard` (FastAPI + SQLAlchemy + React) |
| **Static analysis** | I configured Bandit and reviewed scan results (`tools/`, `samples/`) |
| **Manual review** | I inspected the source code line by line (`audit/findings.md`) |
| **Findings** | I documented 7 vulnerability findings from real code, with severity, CWE, and code references (`audit/AUDIT_REPORT.md`) |
| **Remediation** | I wrote secure code fixes and best-practice recommendations (`audit/remediation.md`) |

---

## 🧩 Project Structure

```
2-Secure-Coding-Review/
├── audit/
│   ├── AUDIT_REPORT.md     # Executive summary, scope, methodology, findings table
│   ├── findings.md         # Detailed per-vulnerability analysis with real code refs
│   └── remediation.md      # Secure code fixes & best practices
├── tools/
│   └── .bandit             # Bandit static analyzer config for IdentityGuard
├── samples/
│   └── bandit_output.txt   # Sample Bandit scan output
└── README.md
```

---

## ⚠️ Findings Covered

| ID | Vulnerability | CWE | Severity | Location |
|----|---------------|-----|----------|----------|
| SC-01 | No rate limiting on login endpoint | CWE-307 | High | `app/auth/routes.py` |
| SC-02 | No server-side JWT revocation / denylist | CWE-613 | High | `app/auth/routes.py`, `app/main.py` |
| SC-03 | Silent exception swallowing in PAM sweeper | CWE-703 | Medium | `app/main.py` |
| SC-04 | Bare `except Exception` fallback masks policy failures | CWE-703 | Medium | `app/iam/access_requests.py` |
| SC-05 | No password reuse / history prevention | CWE-521 | Medium | `app/auth/routes.py` |
| SC-06 | SQLite without migration framework | CWE-1036 | Low | `app/main.py`, README limitations |
| SC-07 | Detailed user info exposed on `/auth/me` | CWE-200 | Low | `app/auth/routes.py` |

---

## 🚀 Quick Start

### Review the target code

```powershell
git clone https://github.com/Alisha-chaudhary/IdentityGuard.git
cd IdentityGuard
# I reviewed app/auth/routes.py, app/main.py, app/iam/access_requests.py
```

### Run Bandit static analysis

```powershell
pip install bandit
bandit -c 2-Secure-Coding-Review/tools/.bandit -r IdentityGuard/app/
```

---

## 📄 Audit Artifacts

| File | Purpose |
|------|---------|
| `audit/AUDIT_REPORT.md` | Executive summary, scope, methodology, findings summary |
| `audit/findings.md` | Detailed analysis per vulnerability with real code snippets |
| `audit/remediation.md` | Secure code fixes and best-practice recommendations |
| `tools/.bandit` | Bandit configuration |
| `samples/bandit_output.txt` | Sample static analysis output |

---

## ⚖️ Authorized Testing Only

This project audits **my own codebase** (IdentityGuard). No third-party, production, or real company systems were accessed.

- This is educational portfolio work.
- Findings are disclosed responsibly within my own repository.
- Do not use these techniques on systems you do not own or have written authorization to test.

---

## 📄 License

[MIT License](../../LICENSE)

---

**Built by Alisha-chaudhary** · Cybersecurity Analyst · CodeAlpha Intern
