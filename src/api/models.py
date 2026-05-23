import uuid
from datetime import datetime
from typing import Any, List

from sqlalchemy import Column, JSON, String
from sqlmodel import Field, Relationship, SQLModel


class Target(SQLModel, table=True):
    __tablename__ = "targets"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str
    type: str
    path: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    scans: List["Scan"] = Relationship(back_populates="target")
    metrics_snapshots: List["MetricsSnapshot"] = Relationship(back_populates="target")


class Project(SQLModel, table=True):
    __tablename__ = "projects"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str
    source_type: str
    target_path: str
    technology: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    scans: List["Scan"] = Relationship(back_populates="project")


class Scan(SQLModel, table=True):
    __tablename__ = "scans"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    target_id: uuid.UUID | None = Field(default=None, foreign_key="targets.id")
    project_id: uuid.UUID | None = Field(default=None, foreign_key="projects.id")
    tool: str
    surface: str
    triggered_by: str
    status: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    raw_output: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    target: Target | None = Relationship(back_populates="scans")
    project: Project | None = Relationship(back_populates="scans")
    findings: List["Finding"] = Relationship(back_populates="scan")


class Finding(SQLModel, table=True):
    __tablename__ = "findings"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_id: uuid.UUID = Field(foreign_key="scans.id")
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    status: str
    first_seen_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen_at: datetime = Field(default_factory=datetime.utcnow)
    fingerprint: str = Field(sa_column=Column(String, unique=True, nullable=False, index=True))

    scan: Scan = Relationship(back_populates="findings")
    remediations: List["Remediation"] = Relationship(back_populates="finding")


class Remediation(SQLModel, table=True):
    __tablename__ = "remediations"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    finding_id: uuid.UUID = Field(foreign_key="findings.id")
    strategy: str
    model_used: str
    prompt_used: str
    patch_diff: str
    applied_at: datetime | None = None
    verified_at: datetime | None = None
    outcome: str

    finding: Finding = Relationship(back_populates="remediations")


class MetricsSnapshot(SQLModel, table=True):
    __tablename__ = "metrics_snapshots"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    target_id: uuid.UUID = Field(foreign_key="targets.id")
    tool: str
    surface: str
    snapshot_at: datetime = Field(default_factory=datetime.utcnow)
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total_open: int = 0
    total_fixed: int = 0

    target: Target = Relationship(back_populates="metrics_snapshots")
