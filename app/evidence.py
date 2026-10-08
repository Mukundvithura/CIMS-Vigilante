"""Evidence storage with SHA-256 integrity (SR-03, UC-04)."""
import hashlib
import uuid
from pathlib import Path

from flask import current_app, g
from werkzeug.utils import secure_filename

from . import audit, incidents
from .auth import ServiceError
from .db import transaction

MAX_BYTES = 5 * 1024 * 1024


def _store():
    return Path(current_app.config["EVIDENCE_DIR"])


def add(incident_id, file_storage):
    if file_storage is None:
        raise ServiceError(400, "file is required")
    data = file_storage.read(MAX_BYTES + 1)
    if not data:
        raise ServiceError(400, "file is empty")
    if len(data) > MAX_BYTES:
        raise ServiceError(413, "file exceeds 5 MB")
    filename = (secure_filename(file_storage.filename or "") or "evidence.bin")[:100]
    digest = hashlib.sha256(data).hexdigest()
    stored_name = uuid.uuid4().hex  # never use the client's filename on disk (path traversal)
    path = _store() / stored_name
    path.write_bytes(data)
    try:
        with transaction() as db:
            incidents.require_workable(db, incident_id)
            cur = db.execute(
                "INSERT INTO evidence (incident_id, filename, stored_name, sha256, size, uploaded_by, uploaded_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (incident_id, filename, stored_name, digest, len(data), g.user["id"], audit.now()),
            )
            audit.record(db, g.user["id"], "EVIDENCE_ADDED", f"incident:{incident_id}",
                         f"evidence:{cur.lastrowid} sha256={digest}")
            return cur.lastrowid, digest
    except Exception:
        path.unlink(missing_ok=True)
        raise
