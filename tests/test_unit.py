"""Unit tests: single functions and rules, no HTTP (Phase 14)."""
import sqlite3

import pytest

from app import audit
from app.auth import ServiceError
from app.db import get_db, transaction
from app.incidents import SEVERITIES, TRANSITIONS, clean_text


def test_clean_text_accepts_normal_text_and_trims():
    assert clean_text("  Phishing mail  ", "title", 200) == "Phishing mail"


@pytest.mark.parametrize("value", ["", "   ", "x" * 201, "bad\x00byte", "bell\x07", 123, None, ["a"]])
def test_clean_text_rejects_bad_values(value):
    with pytest.raises(ServiceError) as err:
        clean_text(value, "title", 200)
    assert err.value.status == 400


def test_clean_text_keeps_newlines_and_tabs():
    assert clean_text("line one\nline two\tend", "note", 200) == "line one\nline two\tend"


def test_severity_set_is_exactly_four_levels():
    assert SEVERITIES == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_only_manager_can_close_and_only_from_resolved():
    assert TRANSITIONS[("RESOLVED", "CLOSED")] == {"MANAGER"}
    assert ("NEW", "CLOSED") not in TRANSITIONS
    assert ("ASSIGNED", "CLOSED") not in TRANSITIONS


def test_audit_digest_is_deterministic_and_depends_on_every_field():
    base = audit._digest("0" * 64, "2026-10-08T10:00:00+00:00", 1, "LOGIN_OK", "user:1", "")
    assert base == audit._digest("0" * 64, "2026-10-08T10:00:00+00:00", 1, "LOGIN_OK", "user:1", "")
    assert base != audit._digest("0" * 64, "2026-10-08T10:00:00+00:00", 2, "LOGIN_OK", "user:1", "")
    assert base != audit._digest("0" * 64, "2026-10-08T10:00:00+00:00", 1, "LOGIN_FAILED", "user:1", "")


def test_verify_chain_detects_an_edit_made_behind_the_triggers(app):
    with app.app_context():
        with transaction() as db:
            for i in range(3):
                audit.record(db, 1, "TEST", f"t:{i}")
        assert audit.verify_chain() == (True, None)

        db = get_db()
        db.execute("DROP TRIGGER audit_no_update")  # an attacker with raw database access
        bad_id = db.execute("SELECT id FROM audit_log WHERE target = 't:1'").fetchone()["id"]
        db.execute("UPDATE audit_log SET details = 'forged' WHERE id = ?", (bad_id,))
        assert audit.verify_chain() == (False, bad_id)


def test_triggers_block_plain_update_and_delete_of_audit_rows(app):
    with app.app_context():
        db = get_db()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM audit_log")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("UPDATE audit_log SET action = 'x'")
