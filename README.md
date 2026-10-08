# CIMS: Cybersecurity Incident Management System

A small web app for security analysts to report, classify, assign, investigate and close incidents, with tamper-evident evidence and a hash-chained audit log.

Built for the 24CYS401 Secure Software Engineering lab exam (problem #25).

## Features

- Report, classify, assign, investigate and close incidents, with a fixed status workflow
- Evidence upload with SHA-256 hashing, and a check that the file still matches its hash
- Role-based access: Reporter, Analyst, Manager, Admin, Auditor
- Need-to-know visibility: incident content is hidden from Admin and Auditor
- Append-only audit log, hash-chained and verifiable
- Account lockout after 5 failed logins, and session timeout

## Stack

Python 3.14, Flask 3.1, SQLite, pytest, bandit, pip-audit.

## Setup

```bash
python -m pip install -r requirements.txt
```

To pin the exact runtime versions used in testing, install from `requirements.lock` instead.

## Configuration

Secrets come from environment variables only:

| Variable | Purpose |
|---|---|
| `CIMS_SECRET_KEY` | Session signing key, at least 32 characters. Required. |
| `CIMS_BOOTSTRAP_ADMIN_PASSWORD` | Creates the first admin account, if none exists. |
| `CIMS_DATABASE` | SQLite file path (default `data/cims.db`). |
| `CIMS_EVIDENCE_DIR` | Evidence folder (default `data/evidence`). |
| `CIMS_COOKIE_SECURE` | Set to `0` for local HTTP testing. Default `1` (HTTPS only). |

## Tests

```bash
python -m pytest -q
```

Tests cover one acceptance criterion per story (EN-7 to EN-33), in `tests/test_backlog.py`.

## Security checks

```bash
python -m bandit -r app
python -m pip_audit -r requirements.txt
```

Last run: bandit found no issues in `app/`, and pip-audit found no known vulnerabilities.

## Project layout

```
app/               Flask app: routes, auth, incidents, evidence, audit, database schema
tests/             pytest suite (one test per Jira story)
docs/              Phase notes
requirements.txt   Runtime and dev dependencies (ranges)
requirements.lock  Pinned runtime versions
```

## Report and diagrams

The full exam report (Phases 1 to 11) and the draw.io diagrams are kept outside this repo, on the project owner's desktop.

## Status

Phases 1 to 11 of the exam are done. Remaining: secure coding and refactoring, Docker and Kubernetes, CI/CD and testing, logging and hardening, and the final review.
