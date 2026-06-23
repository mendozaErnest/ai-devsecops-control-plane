"""Tests for DATABASE_URL path resolution in src/api/database.py."""
from pathlib import Path

from src.api.database import PROJECT_ROOT, _resolve_database_url


def test_relative_sqlite_url_is_anchored_to_project_root():
    """A relative sqlite path must be resolved against PROJECT_ROOT."""
    url = _resolve_database_url("sqlite:///./dev_database.db")
    assert url.startswith("sqlite:///")
    resolved_path = Path(url[len("sqlite:///"):])
    assert resolved_path.is_absolute()
    assert resolved_path.parent == PROJECT_ROOT


def test_absolute_sqlite_url_is_unchanged():
    """An absolute sqlite path must pass through without modification."""
    original = "sqlite:////tmp/test.db"
    assert _resolve_database_url(original) == original


def test_postgresql_url_is_unchanged():
    """Non-sqlite URLs must not be modified."""
    original = "postgresql://user:pass@localhost/dbname"
    assert _resolve_database_url(original) == original


def test_default_database_url_points_to_project_root():
    """The default DATABASE_URL must resolve to a path inside PROJECT_ROOT."""
    from src.api.database import DATABASE_URL
    import os
    # Only test when DATABASE_URL is not overridden by the test environment
    if os.getenv("DATABASE_URL"):
        return
    assert DATABASE_URL.startswith("sqlite:///")
    path = Path(DATABASE_URL[len("sqlite:///"):])
    assert path.is_absolute()
    assert path.parent == PROJECT_ROOT
