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
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",  # CSRF mitigation for the cookie session
        SESSION_COOKIE_SECURE=os.environ.get("CIMS_COOKIE_SECURE", "1") == "1",
    )
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

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

    return app
