# Phase 16: Final Security Review

Full write-up is in the exam report, section 16.

## 1. Traced requirement: SR-03 (evidence is tamper-evident)

| Step | Artefact | What it says for SR-03 |
|---|---|---|
| Requirement | SR-03 (Phase 2) | SHA-256 stored at upload, re-checked on verify |
| Use cases | UC-04 Add Evidence, UC-09 Verify Evidence (Phase 3) | Upload stores the hash; verify compares |
| DFD | P3, D3, D4, flows F05 to F07 and F14, TB2 (Phase 4) | Written inside the trust boundary |
| Threats | T-07 file altered, T-09 bad file name, T-11 hash row edited (Phase 7) | Each changes the file, the name or the stored hash |
| Vulnerabilities | V-06 path traversal (CWE-22), V-08 audit edit (CWE-345) (Phase 7) | Gap: no entry for an editable hash row (see V-10 below) |
| Attack tree | B2 replace the file, B3 change the stored hash (Phase 8) | Path P3 is caught by verify; path P4 needs database admin |
| Refinement | R6 nightly integrity job (Phase 8) | Planned, not built |
| User stories | EN-20 (FR-04), EN-21 (FR-09) (Phase 9) | Upload and verify, with acceptance criteria |
| Sprint task | Sprint 2: EN-20 Done, EN-21 In Progress (Phase 10 snapshot) | EN-21 status is behind the code (see 3) |
| Implementation | app/evidence.py add() and verify(); schema triggers evidence_no_update and evidence_no_delete | SHA-256, random name, all-or-nothing write, immutable rows |
| Tests | tests/test_backlog.py EN-20 and EN-21; tests/test_integration.py | 44 tests pass |
| Deployment control | Dockerfile and k8s: non-root, read-only root, only /app/data writable | Evidence folder is an emptyDir (see limitation 2) |

**Result:** the chain holds from requirement to test.

## 2. Three highest-risk issues and their controls

| Rank | Issue (Phase 7 ID) | Controls in place | Residual risk |
|---|---|---|---|
| 1 | Password guessing against login (T-01, High) | Lockout after 5 failures (EN-8); scrypt hashing (V-01); same error for every failure (T-02); alert A1 | Slow guessing across many accounts is not limited. Per-IP throttle R1 not built |
| 2 | Cross-case access (T-06, High) | Need-to-know check on every read (EN-10); hidden incidents return 404; role checks (EN-9); fuzz and unit tests | Access rules spread across functions. Single access policy R3 not built |
| 3 | Audit log edited by a database admin (T-11, Medium, high impact) | Append-only triggers (EN-24); hash chain and /audit/verify (EN-25); alert A6 | A database admin can drop triggers and rebuild the chain. R4 (chain head export) and R5 (database role) not built |

## 3. Gaps found by the trace

- **V-10 (new, to add to the threat register):** the stored SHA-256 row can be edited by anyone with database write access. Impact: a changed file can be made to match a changed hash. Mitigation: append-only triggers (in place), chain head export R4 (planned), least-privilege database role R5 (planned).
- **R6 not built:** the nightly integrity job would find tampering nobody asked about.
- **EN-21 status:** Jira shows In Progress, but the verify code and its tests are complete. Review and close it in Jira.

## 4. Remaining limitations and future improvements

**Limitation 1: planned controls not built.** CSRF token (T-04), per-IP login throttle (R1), single access policy (R3), chain head export (R4), least-privilege database role (R5), nightly integrity job (R6), TLS at the ingress, and a SIEM. Next step: build R1 and R3 first, as they cover the two highest-risk threats.

**Limitation 2: storage durability and live deployment.** The evidence folder is an emptyDir, so files are lost when the pod restarts. SQLite allows one writer, so the app cannot scale out. There are no backups. The live Kubernetes deploy and the first CI run on GitHub are still pending. Next step: a persistent volume with backups, and PostgreSQL if the system needs to scale.

## 5. Status of all phases

| Phase | Title | Status |
|---|---|---|
| 1 | Agile Process and Development Approach | Done |
| 2 | Requirements Engineering | Done |
| 3 | Requirements Analysis and UML | Done |
| 4 | Data and Information Flow Modeling | Done |
| 5 | Software Architecture and Design | Done |
| 6 | User Interface Design | Done (wireframes in draw.io) |
| 7 | Threat Modeling and Security Analysis | Done |
| 8 | Attack Tree and Security Architecture Refinement | Done |
| 9 | Product Backlog and Jira/Scrum | Done |
| 10 | Sprint Execution and Scrum Metrics | Done (one day of data; daily records to add) |
| 11 | Secure Development and Build Environment | Done |
| 12 | Secure Coding and Refactoring | Done |
| 13 | Containerized Development: Docker and Kubernetes | Done locally (live cluster deploy pending) |
| 14 | CI/CD and Security Testing | Done (CI run on GitHub to confirm) |
| 15 | Logging, Monitoring, Hardening and Secure Deployment | Done (live SIEM and TLS planned) |
| 16 | Final Security Review | Done |
