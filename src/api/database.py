import os
from pathlib import Path

from sqlalchemy import inspect, text
from sqlmodel import SQLModel, create_engine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_URL = f"sqlite:///{PROJECT_ROOT / 'dev_database.db'}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)


def create_db_and_tables() -> None:
    from . import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    ensure_sqlite_schema()


def ensure_sqlite_schema() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    inspector = inspect(engine)

    if "scans" not in inspector.get_table_names():
        return

    scan_columns = {column["name"] for column in inspector.get_columns("scans")}

    with engine.begin() as connection:
        if "project_id" not in scan_columns:
            connection.execute(text("ALTER TABLE scans ADD COLUMN project_id CHAR(32)"))

        if "target_id" in scan_columns:
            # Older development databases created target_id as NOT NULL. New
            # project scans still create a legacy target row for compatibility.
            return
