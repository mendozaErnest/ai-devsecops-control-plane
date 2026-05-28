#!/usr/bin/env python3
"""Clean project scan data and saved remediations from the configured database.

Usage:
    python scripts/clean_project_scan_data.py
    python scripts/clean_project_scan_data.py --yes

By default this is a dry-run. Pass --yes to delete rows.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.database import DATABASE_URL, create_db_and_tables, engine  # noqa: E402


PROJECT_SCAN_WHERE = "project_id IS NOT NULL"


def scalar(sql: str) -> int:
    with engine.connect() as connection:
        value = connection.execute(text(sql)).scalar()
    return int(value or 0)


def collect_counts() -> dict[str, int]:
    project_scan_filter = f"SELECT id FROM scans WHERE {PROJECT_SCAN_WHERE}"
    project_finding_filter = f"SELECT id FROM findings WHERE scan_id IN ({project_scan_filter})"

    return {
        "project_scans": scalar(f"SELECT COUNT(*) FROM scans WHERE {PROJECT_SCAN_WHERE}"),
        "findings": scalar(f"SELECT COUNT(*) FROM findings WHERE scan_id IN ({project_scan_filter})"),
        "remediations": scalar(
            f"SELECT COUNT(*) FROM remediations WHERE finding_id IN ({project_finding_filter})"
        ),
        "finding_audit_events": scalar(
            f"SELECT COUNT(*) FROM finding_audit_events WHERE finding_id IN ({project_finding_filter})"
        ),
        "metrics_snapshots": scalar("SELECT COUNT(*) FROM metrics_snapshots"),
    }


def clean_project_scan_data() -> dict[str, int]:
    counts = collect_counts()
    project_scan_filter = f"SELECT id FROM scans WHERE {PROJECT_SCAN_WHERE}"
    project_finding_filter = f"SELECT id FROM findings WHERE scan_id IN ({project_scan_filter})"

    statements = [
        f"DELETE FROM remediations WHERE finding_id IN ({project_finding_filter})",
        f"DELETE FROM finding_audit_events WHERE finding_id IN ({project_finding_filter})",
        f"DELETE FROM findings WHERE scan_id IN ({project_scan_filter})",
        f"DELETE FROM scans WHERE {PROJECT_SCAN_WHERE}",
        "DELETE FROM metrics_snapshots",
    ]

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))

    return counts


def format_counts(counts: dict[str, int]) -> str:
    labels = {
        "project_scans": "project scans",
        "findings": "findings",
        "remediations": "saved fixes/remediations",
        "finding_audit_events": "finding audit events",
        "metrics_snapshots": "metrics snapshots",
    }
    return "\n".join(f"  - {labels[key]}: {counts[key]}" for key in labels)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Delete project scan data and saved fixes from the configured DB. "
            "Projects, scan profiles, targets and uploaded source files are preserved."
        )
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually delete rows. Without this flag the command only prints a dry-run.",
    )
    args = parser.parse_args()

    create_db_and_tables()
    counts = collect_counts()

    print(f"Database: {DATABASE_URL}")
    if not args.yes:
        print("Dry-run. Rows that would be deleted:")
        print(format_counts(counts))
        print("\nRun with --yes to apply.")
        return 0

    deleted = clean_project_scan_data()
    print("Deleted rows:")
    print(format_counts(deleted))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
