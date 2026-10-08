# Phase 15: Logging, Monitoring, Hardening and Secure Deployment

Evidence date: 8 October 2026. Full write-up is in the exam report, section 15.

## 1. Security events logged

The security log is JSON lines on standard output, for a log collector to pick up.

| Event | Level | Logged when |
|---|---|---|
| LOGIN_OK | INFO | A user signs in |
| LOGIN_FAILED | WARNING | Wrong username or password |
| ACCOUNT_LOCKED | WARNING | Five failed logins in a row |
| ACCESS_DENIED | WARNING | A role check fails |
| ROLE_CHANGED | WARNING | An admin changes a role |
| EVIDENCE_TAMPERED | CRITICAL | A stored file no longer matches its hash |
| AUDIT_CHAIN_BROKEN | CRITICAL | The audit chain check fails |

The audit log (database, hash-chained) also records status changes, severity, notes, evidence and assignments.

## 2. Captured evidence (scenario run)

Five failed logins for one user, then an admin role change and a denied action:

```
WARNING {"event": "LOGIN_FAILED", "user": "analyst", "ip": "127.0.0.1"}   (x4)
WARNING {"event": "ACCOUNT_LOCKED", "user": "analyst", "ip": "127.0.0.1"}
WARNING {"event": "LOGIN_FAILED", "user": "analyst", "ip": "127.0.0.1"}
INFO    {"event": "LOGIN_OK", "user": "admin", "ip": "127.0.0.1"}
WARNING {"event": "ROLE_CHANGED", "by": "admin", "target": 4, "role": "MANAGER"}
WARNING {"event": "ACCESS_DENIED", "user": "victim", "endpoint": "create_user"}
```

## 3. Alert rules

| ID | Alert | Rule | Severity | Response |
|---|---|---|---|---|
| A1 | Brute force | 5+ LOGIN_FAILED for one user in 10 min | High | Check the IP, keep the account locked |
| A2 | Account locked | Any ACCOUNT_LOCKED | Medium | Confirm with the user before unlocking |
| A3 | Access denied spike | 10+ ACCESS_DENIED from one IP in 5 min | High | Block the IP, review attempts |
| A4 | Role changed | Any ROLE_CHANGED | High | Auditor reviews the same day |
| A5 | Evidence tampered | Any EVIDENCE_TAMPERED | Critical | Freeze the incident, keep a copy |
| A6 | Audit chain broken | Any AUDIT_CHAIN_BROKEN | Critical | Stop changes, compare with last good export |
| M1 | Server errors | 5xx rate above 1% over 5 min | High | Check the latest deploy |
| M2 | Health check failures | Liveness fails 3 times | High | Pod restarts (NFR-02) |
| M3 | Slow lists | Over 1 s at 10,000 incidents | Medium | Check the query plan |
| M4 | Evidence volume | Over 80% of 1 GiB | Medium | Clean up or extend, after review |

Checked against the scenario log: A1, A2 and A4 fire. A3, A5 and A6 do not, because the scenario did not reach their thresholds. Live alerting needs a log collector and a SIEM, which are not set up.

## 4. Hardening checklist

| Area | Status | Evidence |
|---|---|---|
| Access: no default admin password | Done | Admin created from env only (EN-27) |
| Ports and services | Done | Container exposes 8000 only; service is ClusterIP |
| Secrets | Done | Environment or Kubernetes Secret; git history checked |
| Updates | Done | Pinned lock file; pip-audit in CI; Werkzeug 3.1.9 |
| Permissions | Done | Non-root UID 10001; read-only root; only data writable |
| Least privilege (database) | Planned | Role R5, not built |
| Transport (TLS) | Partly | Secure cookie flag on; TLS at ingress not set up |
| Log retention and shipping | Planned | Needs collector and SIEM |

## 5. Physical and operational controls

- Disk encryption on the laptop (BitLocker): documented, check it is on.
- Screen lock after short idle: documented.
- Separation of duties (only the Manager closes): built into the app.
- Pull-request review on GitHub: planned (branch rules set; approvals 0 for a solo project).
- Backup and restore test: planned, not done.
- Credential rotation: rotate `CIMS_SECRET_KEY` and the admin password on any suspicion.
- Incident response contact: the responses in section 3.

## 6. Secure deployment checklist

- [x] Image built from pinned dependencies
- [x] bandit and pip-audit clean before deploying
- [x] Secrets created with kubectl, not in YAML
- [x] Namespace uses the restricted Pod Security Standard
- [x] Container runs non-root, read-only, no capabilities (checked locally)
- [x] Health check and restart policy in the manifest
- [ ] Deployed to a live cluster and checked (Kubernetes not yet enabled)
- [ ] TLS at the ingress
- [ ] Database least-privilege role
- [ ] Security logs shipped to a collector or SIEM
