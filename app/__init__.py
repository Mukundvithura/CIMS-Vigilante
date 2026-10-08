"""CIMS - Cybersecurity Incident Management System (24CYS401 lab)."""
import logging
import os
import sys
from pathlib import Path

from flask import Flask, jsonify

from .auth import ServiceError


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        # Secrets come from the environment / K8s Secret only (SR-09). Never hard-coded.
        SECRET_KEY=os.environ.get("CIMS_SECRET_KEY"),
        DATABASE=os.environ.get("CIMS_DATABASE", "data/cims.db"),
        EVIDENCE_DIR=os.environ.get("CIMS_EVIDENCE_DIR", "data/evidence"),
        MAX_CONTENT_LENGTH=6 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",  # CSRF mitigation for the cookie session
        SESSION_COOKIE_SECURE=os.environ.get("CIMS_COOKIE_SECURE", "1") == "1",
        PERMANENT_SESSION_LIFETIME=1800,
    )
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["EVIDENCE_DIR"]).mkdir(parents=True, exist_ok=True)

    sec = logging.getLogger("cims.security")
    if not sec.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        sec.addHandler(handler)
        sec.setLevel(logging.INFO)

    from . import auth, db, routes
    app.teardown_appcontext(db.close_db)
    app.register_blueprint(routes.bp)

    with app.app_context():
        db.init_db()

    @app.errorhandler(ServiceError)
    def service_error(e):
        return jsonify(error=e.message), e.status

    @app.errorhandler(Exception)
    def unexpected(e):
        code = getattr(e, "code", 500)
        if code == 500:
            app.logger.exception("unhandled error")  # details to the log, never to the client
            return jsonify(error="internal error"), 500
        return jsonify(error=getattr(e, "name", "error")), code

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        # Only our own scripts run (no inline JS), so injected markup can't execute. Fonts come from Google.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        resp.headers["Cache-Control"] = "no-store"  # incident data must not sit in caches
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    return app
