import os
from pathlib import Path

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine, select


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATABASE_URL = f"sqlite:///{PROJECT_ROOT / 'dev_database.db'}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

_DEFAULT_PROFILES = [
    {
        "name": "Python SAST",
        "description": "Bandit + Semgrep dual-engine for Python projects",
        "technologies": "[\"python\", \"django\", \"flask\"]",
        "sast_enabled": True,
        "sast_tools": "both",
    },
    {
        "name": "Angular SAST",
        "description": "Semgrep for Angular/TypeScript projects",
        "technologies": "[\"angular\", \"typescript\"]",
        "sast_enabled": True,
        "sast_tools": "semgrep",
    },
    {
        "name": "Java SAST",
        "description": "Semgrep for Java projects",
        "technologies": "[\"java\", \"java-spring\"]",
        "sast_enabled": True,
        "sast_tools": "semgrep",
    },
    {
        "name": "Full Scan",
        "description": "SAST enabled (DAST and Quality available when adapters are installed)",
        "technologies": "[\"python\", \"django\", \"flask\", \"angular\", \"typescript\", \"java\", \"java-spring\"]",
        "sast_enabled": True,
        "sast_tools": "both",
        "dast_enabled": False,
        "quality_enabled": False,
    },
]


def create_db_and_tables() -> None:
    from . import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    ensure_sqlite_schema()


def seed_default_profiles() -> None:
    from .models import ScanProfile

    with Session(engine) as session:
        existing_names = {
            profile.name
            for profile in session.exec(select(ScanProfile)).all()
        }
        for data in _DEFAULT_PROFILES:
            if data["name"] not in existing_names:
                session.add(ScanProfile(**data))
        session.commit()


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
            pass

    if "projects" in inspector.get_table_names():
        project_columns = {col["name"] for col in inspector.get_columns("projects")}
        with engine.begin() as connection:
            if "scan_profile_id" not in project_columns:
                connection.execute(text("ALTER TABLE projects ADD COLUMN scan_profile_id INTEGER"))

    if "scanprofile" in inspector.get_table_names():
        profile_columns = {col["name"] for col in inspector.get_columns("scanprofile")}
        with engine.begin() as connection:
            if "technologies" not in profile_columns:
                connection.execute(text("ALTER TABLE scanprofile ADD COLUMN technologies TEXT"))
            if "infra_enabled" not in profile_columns:
                connection.execute(text("ALTER TABLE scanprofile ADD COLUMN infra_enabled INTEGER NOT NULL DEFAULT 0"))
            if "infra_tools" not in profile_columns:
                connection.execute(text("ALTER TABLE scanprofile ADD COLUMN infra_tools TEXT"))

    if "findings" in inspector.get_table_names():
        finding_columns = {col["name"] for col in inspector.get_columns("findings")}
        with engine.begin() as connection:
            if "tool" not in finding_columns:
                connection.execute(text("ALTER TABLE findings ADD COLUMN tool TEXT"))
            if "regression_count" not in finding_columns:
                connection.execute(text("ALTER TABLE findings ADD COLUMN regression_count INTEGER NOT NULL DEFAULT 0"))
            if "sla_deadline" not in finding_columns:
                connection.execute(text("ALTER TABLE findings ADD COLUMN sla_deadline DATETIME"))

    if "remediations" in inspector.get_table_names():
        rem_columns = {col["name"] for col in inspector.get_columns("remediations")}
        with engine.begin() as connection:
            if "pr_url" not in rem_columns:
                connection.execute(text("ALTER TABLE remediations ADD COLUMN pr_url TEXT"))
            if "pr_branch" not in rem_columns:
                connection.execute(text("ALTER TABLE remediations ADD COLUMN pr_branch TEXT"))
