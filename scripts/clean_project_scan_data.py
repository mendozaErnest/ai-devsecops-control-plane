#!/usr/bin/env python3
"""Clean scan data, saved remediations and optional saved profiles from the DB.

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


def scalar(sql: str) -> int:
    with engine.connect() as connection:
        value = connection.execute(text(sql)).scalar()
    return int(value or 0)


def collect_counts() -> dict[str, int]:
    finding_filter = "SELECT id FROM findings"

    return {
        "scans": scalar("SELECT COUNT(*) FROM scans"),
        "findings": scalar("SELECT COUNT(*) FROM findings"),
        "remediations": scalar(
            f"SELECT COUNT(*) FROM remediations WHERE finding_id IN ({finding_filter})"
        ),
        "finding_audit_events": scalar(
            f"SELECT COUNT(*) FROM finding_audit_events WHERE finding_id IN ({finding_filter})"
        ),
        "metrics_snapshots": scalar("SELECT COUNT(*) FROM metrics_snapshots"),
        "scan_profiles": scalar("SELECT COUNT(*) FROM scanprofile"),
    }


def clean_project_scan_data(include_profiles: bool = False) -> dict[str, int]:
    counts = collect_counts()
    finding_filter = "SELECT id FROM findings"

    statements = [
        f"DELETE FROM remediations WHERE finding_id IN ({finding_filter})",
        f"DELETE FROM finding_audit_events WHERE finding_id IN ({finding_filter})",
        "DELETE FROM findings",
        "DELETE FROM scans",
        "DELETE FROM metrics_snapshots",
    ]

    if include_profiles:
        statements.extend([
            "UPDATE projects SET scan_profile_id = NULL",
            "DELETE FROM scanprofile",
        ])

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))

    return counts


def format_counts(counts: dict[str, int]) -> str:
    labels = {
        "scans": "scans",
        "findings": "findings",
        "remediations": "saved fixes/remediations",
        "finding_audit_events": "finding audit events",
        "metrics_snapshots": "metrics snapshots",
        "scan_profiles": "saved scan profiles",
    }
    return "\n".join(f"  - {labels[key]}: {counts[key]}" for key in labels)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Delete project scan data and saved fixes from the configured DB. "
            "Projects, targets and uploaded source files are preserved."
        )
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually delete rows. Without this flag the command only prints a dry-run.",
    )
    parser.add_argument(
        "--profiles",
        action="store_true",
        help="Also delete saved scan profiles and detach them from projects.",
    )
    args = parser.parse_args()

    create_db_and_tables()
    counts = collect_counts()

    print(f"Database: {DATABASE_URL}")
    if not args.yes:
        print("Dry-run. Rows that would be deleted:")
        visible_counts = counts if args.profiles else {**counts, "scan_profiles": 0}
        print(format_counts(visible_counts))
        print("\nRun with --yes to apply.")
        return 0

    deleted = clean_project_scan_data(include_profiles=args.profiles)
    if not args.profiles:
        deleted = {**deleted, "scan_profiles": 0}
    print("Deleted rows:")
    print(format_counts(deleted))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
