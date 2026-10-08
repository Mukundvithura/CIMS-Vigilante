# Phase 1: Agile Process and Development Approach (6 marks)

**Project:** #25 Cybersecurity Incident Management System (CIMS)
**Assumption A1:** the examiner's problem statement is the one given (report, classify, assign, evidence, track, update status, close, immutable audit history).

## 1. Chosen approach: Scrum with XP practices

| Element | What we use | Why |
|---|---|---|
| Framework | Scrum (2 sprints, Jira board) | Matches Phases 9–10 (backlog, sprints, burndown). |
| Engineering | XP: TDD, small commits, pair review, continuous integration, refactoring | Security checks run on every change, not once at the end. |
| Roles | Product Owner (Manager role), Scrum Master (student), Dev Team (student) | Mirrors the system's own role separation. |

**Justification:** The system holds sensitive incident data and must be correct before it is fast. Scrum gives short, reviewable increments. XP practices (tests first, CI on every push) catch security regressions early, which is cheaper than fixing them at the end.

## 2. Manifesto principles mapped to CIMS

| # | Agile Manifesto principle | Application in CIMS |
|---|---|---|
| P1 | Satisfy the customer through early and continuous delivery of valuable software | Sprint 1 delivers a working report → classify → assign flow; Sprint 2 adds evidence and closure. |
| P2 | Welcome changing requirements, even late in development | Stories can be re-prioritised each sprint (e.g. if the examiner adds a new actor). |
| P3 | Working software is the primary measure of progress | Done = tests pass, bandit clean, deployed to the container. Documents alone don't count. |
| P4 | Business people and developers work together daily | The Manager (Product Owner) approves each story's acceptance criteria before the sprint starts. |
| P5 | Continuous attention to technical excellence and good design | Refactoring step in every sprint; the status-transition table replaces scattered if-statements (see §3). |
| P6 | Simplicity: maximising work not done is essential | One monolith, SQLite, no extra services. Only the features in the SRS are built. |

## 3. Refactoring opportunities (design level; code before/after in Phase 12)

**R1: Status changes scattered in route handlers → one transition table**

Before (planned first draft):
```python
if incident.status == "ASSIGNED" and user.role == "ANALYST":
    incident.status = "INVESTIGATING"
elif incident.status == "INVESTIGATING" and user.role == "ANALYST":
    incident.status = "RESOLVED"
elif incident.status == "RESOLVED" and user.role == "MANAGER":
    incident.status = "CLOSED"
```
After:
```python
TRANSITIONS = {
    ("ASSIGNED", "INVESTIGATING"): {"ANALYST"},
    ("INVESTIGATING", "RESOLVED"): {"ANALYST"},
    ("RESOLVED", "CLOSED"): {"MANAGER"},
}
```
**Gain:** one place to read and audit the workflow. Invalid moves are rejected by default, which is the secure choice.

**R2: Input checks repeated in every route → one validator at the trust boundary**

Before: each route does its own `if not title:` check, and some forget the length limit.
After: one `clean_text(value, field, max_len)` function, called by every route that accepts text.
**Gain:** one rule to test (length, control characters, empty input), and no route can skip it.

## 4. Limitations and risks of Agile for a security-critical system

| # | Risk | Mitigation |
|---|---|---|
| L1 | Security work gets dropped when sprint time runs short ("we'll harden it later") | Security acceptance criteria on every story, plus a Definition of Done that includes passing `bandit` and the security tests. |
| L2 | Light upfront design means the security architecture (evidence hashing, audit chain, trust boundaries) is hard to retrofit late | Threat model and DFD (Phases 4–7) are completed before Sprint 1 coding starts. A security spike in Sprint 1 proves the audit chain works. |

## Exam answer (short)
**Scrum + XP** because CIMS is security-critical and needs short, tested increments. Five principles mapped: early delivery, changing requirements, working software, daily business–dev contact, technical excellence. Two refactorings: transition table and a single input validator. Two risks: security dropped under pressure (fix: security in Definition of Done) and late retrofit of security design (fix: threat model before coding).

## MUST KNOW
- Scrum + XP is the chosen approach, with a reason.
- Two Agile risks, each with a mitigation.
