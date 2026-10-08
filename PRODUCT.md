# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Security Operations Centre (SOC) staff in one organisation, working at desktops/laptops. Five roles:
- **Reporter**: reports a suspected incident (title + description).
- **Analyst**: classifies, investigates, adds evidence and notes, moves status.
- **Manager**: assigns incidents, approves resolution, and is the only role that closes incidents.
- **Admin**: manages user accounts; cannot see incident content.
- **Auditor**: reads the audit log only.

## Product Purpose
CIMS ("VIGILANTE") lets a SOC report, classify, assign, investigate, and close cybersecurity incidents while keeping evidence and history trustworthy. Success: every incident moves through a clear lifecycle, every action is attributable, and nothing can be silently changed.

## Positioning
Integrity is the product: SHA-256 hashed evidence verified on demand, a hash-chained append-only audit log, and strict role separation (the Admin can't read incidents; only the Manager closes).

## Operating Context
- Daily working tool for SOC analysts; long sessions, scanning lists, acting on one incident at a time.
- Lifecycle: NEW → TRIAGED → ASSIGNED → INVESTIGATING → RESOLVED → CLOSED; RESOLVED → INVESTIGATING reopens.
- Also used for a university lab exam (24CYS401); screens are captured for the report.

## Capabilities and Constraints
- Flask + SQLite backend, JSON API; single-page frontend in `app/static/` (plain HTML/CSS/JS).
- Strict CSP: `script-src 'self'`, no inline scripts/styles from third parties; Google Fonts is the only external source.
- Evidence uploads max 5 MB, stored under random names.
- Up to ~10,000 incidents; lists must load within 1 second.
- Local accounts only, with lockout after failed logins.

## Brand Commitments
- Name: **VIGILANTE**, tagline "Security Incident Mgmt".
- Assets: `app/static/logo.png`, `app/static/shield.png`.
- Accent colour follows the logo blue.

## Evidence on Hand
- No real customers, testimonials, or metrics. Don't invent any.

## Product Principles
1. Trust over speed: never hide who did what, or when.
2. Role clarity: each role only sees and does what it's allowed to.
3. Scan first: an analyst should spot status and severity at a glance.
4. Fail safe: errors are clear and never leak sensitive data.

## Accessibility & Inclusion
WCAG 2.1 AA: contrast, full keyboard use, labelled form fields. Desktop/laptop only.
