import sqlite3
from contextlib import contextmanager
from pathlib import Path

from flask import current_app, g


def get_db():
    if "db" not in g:
        # isolation_level=None -> we control transactions explicitly (see transaction()).
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=10, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def transaction():
    """BEGIN IMMEDIATE takes the write lock up front, so two workers can never
    read the same last audit hash and fork the chain."""
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def init_db():
    get_db().executescript((Path(__file__).parent / "schema.sql").read_text())
