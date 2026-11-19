"""
Data models for rcdebug findings, telemetry snapshots, and audit sessions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


SEVERITY_ORDER = {
    "INFO": 1,
    "WARN": 2,
    "CRITICAL": 3,
}


SeverityFilter = str | set[str] | frozenset[str] | tuple[str, ...] | list[str] | None


def normalize_severity(sev: str) -> str:
    upper = (sev or "INFO").strip().upper()
    if upper in ("CRITICAL", "CRIT", "HIGH", "ERROR"):
        return "CRITICAL"
    if upper in ("WARN", "WARNING", "MEDIUM"):
        return "WARN"
    return "INFO"


def normalize_filter_set(filter_level: SeverityFilter) -> frozenset[str] | None:
    if not filter_level:
        return None
    if isinstance(filter_level, str):
        return frozenset({normalize_severity(filter_level)})
    levels = frozenset(normalize_severity(item) for item in filter_level if item)
    return levels or None


def format_filter_label(filter_level: SeverityFilter) -> str:
    levels = normalize_filter_set(filter_level)
    if not levels:
        return "ALL (CRITICAL, WARN, INFO)"
    ordered = sorted(levels, key=lambda s: -SEVERITY_ORDER.get(s, 0))
    return ", ".join(ordered)


def matches_filter(severity: str, filter_level: SeverityFilter) -> bool:
    """
    Returns True if `severity` should be displayed under `filter_level`.
    If `filter_level` is None/empty, all severities are shown.
    Accepts a single severity string or a collection of severities (e.g. {'CRITICAL', 'WARN'}).
    """
    levels = normalize_filter_set(filter_level)
    if not levels:
        return True
    return normalize_severity(severity) in levels


@dataclass
class Finding:
    severity: str
    title: str
    path: str
    flaw: str
    abuse: str
    fix: str
    category: str = "General"
    code_example: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    metadata: dict[str, Any] = field(default_factory=dict)
    rank: int = 999999
    confidence: float = 1.0

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)

    def sort_key(self) -> tuple[int, int, float, str]:
        return (-SEVERITY_ORDER.get(self.severity, 0), self.rank, -self.confidence, self.title)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "path": self.path,
            "flaw": self.flaw,
            "abuse": self.abuse,
            "fix": self.fix,
            "category": self.category,
            "code_example": self.code_example,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class MemorySnapshot:
    timestamp: str
    elapsed_sec: float
    workspace_instances: int
    player_instances: int
    total_memory_mb: float
    class_breakdown: dict[str, int] = field(default_factory=dict)


@dataclass
class RemoteTrafficStat:
    remote_path: str
    remote_type: str
    total_calls: int = 0
    peak_rate_per_sec: float = 0.0
    last_rate_per_sec: float = 0.0
    has_cooldown_warning: bool = False
    last_payload_preview: str = ""


@dataclass
class AuditSession:
    mode: str  # "client" or "server"
    started_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    target_name: str = "Roblox Studio"
    findings: list[Finding] = field(default_factory=list)
    memory_snapshots: list[MemorySnapshot] = field(default_factory=list)
    remote_traffic: dict[str, RemoteTrafficStat] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> bool:
        """
        Adds a finding if an identical (title, path) isn't already recorded
        (unless it's a live rate-limit/memory spike event).
        Returns True if added.
        """
        for existing in self.findings:
            if (
                existing.title == finding.title
                and existing.path == finding.path
                and finding.category not in ("MemoryDiff", "RemoteTraffic")
            ):
                return False
        self.findings.append(finding)
        return True

    def counts_by_severity(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "WARN": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
