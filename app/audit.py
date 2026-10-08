"""Hash-chained audit log (SR-05) + structured security log for monitoring (Phase 15)."""
import hashlib
import json
import logging
from datetime import datetime, timezone

from flask import has_request_context, request


GENESIS = "0" * 64
seclog = logging.getLogger("cims.security")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(prev_hash, ts, actor_id, action, target, details):
    payload = json.dumps([prev_hash, ts, actor_id, action, target, details], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def record(db, actor_id, action, target, details=""):
    """Append one audit row. Call inside db.transaction() so the audit row commits
    atomically with the change it describes."""
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else GENESIS
    ts = now()
    db.execute(
        "INSERT INTO audit_log (ts, actor_id, action, target, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
        (ts, actor_id, action, target, details, prev, _digest(prev, ts, actor_id, action, target, details)),
    )


def security_event(event, level=logging.INFO, **fields):
    """One JSON line per security event -> stdout -> Splunk/ELK (Phase 15)."""
    entry = {"ts": now(), "event": event, **fields}
    if has_request_context():
        entry["ip"] = request.remote_addr
    seclog.log(level, json.dumps(entry))
