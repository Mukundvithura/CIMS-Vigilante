---
version: 1
slug: "app-static-index-html"
primary_target: "app/static/index.html"
related_targets: ["app/static/app.js","app/static/vigilante.css"]
---

# VIGILANTE app shell (all screens)

Scope: the single-page app in app/static (login, dashboard, incidents, incident detail, users, audit). Mode: Operate.
Audience: SOC staff in five roles (see PRODUCT.md). Job: move incidents through the lifecycle with trustworthy evidence and history.
Constraints: strict CSP (no inline styles/scripts, img-src 'self', fonts only from Google Fonts), desktop/laptop, WCAG 2.1 AA.
Build path: code-led (no image generation available).
History: Chain of Custody was built first; the user then switched to the assigned direction, Investigation Docket (2026-10-08).

## Direction contract

THESIS: Every incident is an investigation record, numbered, sequenced in time and closed with a finding. Refuses the category default: navy-black canvas, neon-cyan glow, KPI-card grid and donut.

OWN-WORLD: Air-accident investigation reports and their public dockets. Navy docket-binder rail (#14284b), report-white work area, grey ruled lines, logo blue only on things you can press, red for critical, amber for high, green only for a verified finding and a resolved case (the report's positive finding). Public Sans, the government-report grotesk, with hierarchy by scale contrast: case numbers and counts set large, labels tiny. JetBrains Mono only for hashes. Work areas are ruled report pages, not floating cards.

STORY: An analyst opens VIGILANTE, sees the docket of open cases and what needs them, opens one, reads it like a report (summary, sequence of events, exhibits), adds an entry or an exhibit, and trusts the record because every entry is numbered and timed.

FIRST VIEWPORT: Navy rail on the left (logo, nav, user). The dashboard is a docket index: a status-of-investigations line across six stages with large counts, where the stages awaiting the signed-in role are inked navy; the critical case below it; then the docket table, with large case numbers, beside the severity breakdown. Report Incident is the primary blue action, top right.

FORM: Investigation Docket (air-accident reports and public dockets); my grounded rank 7, the assigned roll; seed key 26add7fa. Signature move: the sequence of events, where entries are numbered 1, 2, 3 with times right-aligned tight against a fixed margin. Raises: scale contrast (from the variable-font specimen), accent only on pressables (from the warm consumer app), a fixed lifecycle ink set with one reserved ink for the current stage (from the orienteering map), right-aligned times (from the cassette J-card). Evidence items are numbered exhibits; integrity checks read as findings.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
