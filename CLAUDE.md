# CIMS: Cybersecurity Incident Management System (24CYS401 lab exam)

Read this first in every new session. It says what is done, what is next, and how the user likes to work.

## The exam
- Course: 24CYS401 Secure Software Engineering, End Semester Integrated Lab Exam. 3 hours, 100 marks, 16 phases.
- Official instructions: `C:\Users\Mukund Karthikeyan\Desktop\24CYS401_End_Semester_Integrated_Secure_Software_Engineering_Lab_Exam_General_Instructions.docx`
- Assigned problem: **#25 Cybersecurity Incident Management System**. Analysts report, classify, assign, add evidence, track investigation, update status and close incidents. The system keeps an immutable-style audit history. Security challenges: evidence integrity, role separation, audit logs, unauthorized modification, privilege escalation, sensitive information.
- The 16 phases, in order: 1 Agile (6), 2 Requirements (7), 3 UML/Requirements Analysis (7), 4 Data and Information Flow (7), 5 Architecture and Design (7), 6 UI Design (5), 7 Threat Modeling (10), 8 Attack Tree (6), 9 Backlog and Jira (7), 10 Sprint Metrics (7), 11 Secure Build (6), 12 Secure Coding (4), 13 Docker and Kubernetes (7), 14 CI/CD and Testing (7), 15 Logging and Hardening (5), 16 Final Security Review (1).
- The examiner expects all phases to trace back to each other. Requirement IDs (FR, NFR, SR), use case IDs (UC), DFD process/store IDs (P, D), and threat IDs (T) are reused across phases so marks aren't lost to inconsistency.

## Status (as of 2026-10-08)

| Phase | Status | Where |
|---|---|---|
| 1 Agile | Done | Report section 1; also `docs/phase01_agile.md` (older markdown copy) |
| 2 Requirements | Done | Report section 2. FR-01 to FR-13, NFR-01 to NFR-06, SR-01 to SR-10, assumptions A2 to A5 |
| 3 UML / Analysis | Done | Report section 3. Use case diagram, UC-01 to UC-14, two use case specs (UC-04 Add Evidence, UC-07 Close Incident), analysis model 3.6 (step table, scenario "Investigate and Close Incident", assumption A6) |
| 4 Data / DFD | Done | Report section 4. ER diagram, DFD Level 0 and 1 with trust boundaries (TB1 to TB4), data flow table F01 to F14, consistency table |
| 5 Architecture | Done | Report section 5: layered monolith justification, Figure 5.1 architecture image, components C1 to C7, 17 endpoints, 6 patterns/principles, requirement-to-component mapping. Draw.io source: `CIMS_Phase05_Architecture.drawio` |
| 6 to 16 | Not started | |

Note: the report now has 5 images (Figure 3.1, Figures 4.1 to 4.3, Figure 5.1).

## Files and where they are
- **Master report (Word):** `C:\Users\Mukund Karthikeyan\Desktop\CIMS_SSE_Exam_Report.docx`. Built with python-docx. Contains a table of contents with page numbers that Word refreshes on open. Sections 1 to 4 are done. Images are embedded (Figure 3.1 use case screenshot, Figures 4.1 to 4.3 ER and DFDs).
- **Diagram images (PNG, copied from screenshots):** `C:\Users\Mukund Karthikeyan\Desktop\CIMS_Diagram_Images\` (`phase4_er.png`, `phase4_dfd_level0.png`, `phase4_dfd_level1.png`)
- **draw.io files (Desktop):**
  - `CIMS_UseCase_Diagram.drawio`: Phase 3 use case diagram. Actors are colour-coded.
  - `CIMS_Sequence_Investigate_Close.drawio`: Phase 3 sequence diagram. Not in the report. The user said it isn't needed. Keep it as an optional extra.
  - `CIMS_Phase04_Diagrams.drawio`: 3 pages (ER, DFD Level 0, DFD Level 1).
  - `CIMS_Phase05_Architecture.drawio`: Phase 5 architecture, pending review.
- **Code (project folder):** `CIMS_SSE_Exam\app\`. `schema.sql` (tables, append-only triggers), `db.py`, `audit.py` (hash chain), `auth.py` (login, lockout, RBAC, roles), `incidents.py` (state transitions, validation), `evidence.py` (SHA-256 upload and verify), `routes.py` (17 endpoints), `__init__.py` (app factory, headers, error handling). **Git (2026-10-08):** own repo in this folder (branch `main`, no remote). 25 commits, one per Jira story EN-7 to EN-31 (Jira project EN on mukundkarthikeyan380.atlassian.net), each verified by `tests/test_backlog.py::test_en<N>_*` (25 tests, ~10 s). Not done/uncommitted: EN-32 NFR-05 (Dockerfile/container), EN-33 NFR-06 (CI pipeline). CLAUDE.md and docs/ are untracked.
- **Frontend (2026-10-08), brand "VIGILANTE":** `app/static/` (`index.html`, `vigilante.css`, `app.js`, `logo.png`, `shield.png`). Single page served at `/`, calls the JSON API. Style copied from `Desktop\stitch_sentinelir_soc_incident_dashboard` (DESIGN.md tokens), accent shifted to the logo blue. No Tailwind/inline JS, so the CSP stays strict (`script-src 'self'`; Google Fonts only). Added `GET /me` and `GET /` to `routes.py`. Screens: Login, Dashboard, Incidents, Incident detail (classify/assign/status/notes/evidence), User Management (ADMIN), Audit Log (AUDITOR). Tested in a browser for all 5 roles. These are Phase 6 screenshot material.
- **Run locally:** set `CIMS_SECRET_KEY` (32+ chars), `CIMS_COOKIE_SECURE=0` (plain http), `CIMS_BOOTSTRAP_ADMIN_PASSWORD`, then `python -c "from app import create_app; create_app().run(port=5055)"` and open http://127.0.0.1:5055.
- **Plan file:** `C:\Users\Mukund Karthikeyan\.claude\plans\the-problem-statement-or-zesty-pelican.md`
- **Memory:** `C:\Users\Mukund Karthikeyan\.claude\projects\C--\memory\project_sse_lab_exam.md` (exam format and rules)

## Decisions made (don't re-ask)
- Stack: Python Flask + SQLite, pytest, bandit, pip-audit, Docker, Minikube, GitHub Actions. The user said "any stack, best result".
- **The assistant writes all the code.** The user does not write code.
- **One phase at a time.** After each phase, stop and wait for the user to say "next" or "proceed". Don't start the next phase on your own.
- **Diagrams in draw.io** (`.drawio` files). Put the screenshot into the report when the user asks.
- Roles: REPORTER, ANALYST, MANAGER, ADMIN, AUDITOR. Admin manages users but cannot see incident content. Only the Manager closes incidents. Auditor reads the audit log only.
- Status flow: NEW → TRIAGED → ASSIGNED → INVESTIGATING → RESOLVED → CLOSED. RESOLVED → INVESTIGATING is the reopen path (UC-06a).
- Evidence limit 5 MB, SHA-256 at upload, stored under a random name. Audit log is hash-chained and append-only (triggers block UPDATE/DELETE).
- Assumptions in the report: A1 problem statement given; A2 up to 10,000 incidents; A3 5 MB evidence; A4 one organisation, local accounts; A5 exam user types mapped to our roles; A6 the scenario in 3.6 replaces the exam's example ("Attend Examination...") so it fits CIMS.

## User preferences
- **Short, simple messages.** The user is a beginner and gets overwhelmed by long replies. Use short bullet points.
- **Don't add anything unrequested.** Keep diagrams and docs concise and easy to read.
- **Stop and ask** before starting the next phase or doing anything outward-facing.
- Follow the example layout of the reference file `SkillSim_Secure_Software_Engineering_Capstone_Report_Final.docx` (fonts, colours, tables, header and footer, TOC). Copy the format only. Don't copy its content.

## Working gotchas
- **Word lock:** `python-docx` can't save while the report is open in Word (PermissionError). Ask the user to close it, then rerun.
- **File-creation hook:** the first Write of any new file is blocked by a "fact-forcing" check. The fix is to resend the same Write with a short statement of: who calls the file, that there are no data schemas, and the user's verbatim instruction. This happens about every new file.
- **Bash heredocs:** the closing `EOF` must be alone on its own line. A missing one has broken several runs. Writing the script to a file is more reliable.
- **Adding a phase to the report:** pattern used so far. Open the report, add the phase body, then insert new TOC entries after the last TOC entry, moving the TOC field's end marker. Set headings with `d.add_heading`. Diagram callouts are replaced by images (picture plus a grey caption).
- **Diagram checks:** after writing a `.drawio` file, parse it with `xml.etree` to check it's valid. Diagrams are rendered by the user, not by the assistant.
- Old unused files on the Desktop: `SSE_Report.docx`, `Mukund_Karthikeyan_CH.SC.U4CYS23027.docx`, `SkillSim_...docx` (reference only). Don't touch them.

## Next step
1. Ask the user to review the Phase 5 section in the report.
2. Once they say "next", start Phase 6 (UI design: 4 screens, golden rules, wireframes).
