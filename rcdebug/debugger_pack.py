"""
120-Source Light Luau Debugger Pack loader and static probe engine.

Loads 120 lightweight Luau debugging, linting, profiling, memory-leak,
and security probes from data/luau_debugger_pack_120.json.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Pattern

from .models import Finding

PACK_JSON_PATH = Path(__file__).resolve().parent / "data" / "luau_debugger_pack_120.json"
EXPECTED_PACK_COUNT = 120


@dataclass(frozen=True, slots=True)
class DebuggerProbe:
    id: str
    source: str
    category: str
    severity: str
    name: str
    pattern: Pattern[str]
    raw_pattern: str
    root_cause: str
    fix: str


class LuauDebuggerPack:
    """Compiled 120-probe Light Luau Debugger Pack."""

    def __init__(self, probes: tuple[DebuggerProbe, ...]) -> None:
        self.probes = probes
        self._by_id: dict[str, DebuggerProbe] = {p.id: p for p in probes}

    def count(self) -> int:
        return len(self.probes)

    def get(self, probe_id: str) -> DebuggerProbe | None:
        return self._by_id.get(probe_id.upper())

    def search(self, query: str = "", limit: int = 20) -> list[DebuggerProbe]:
        q = query.strip().lower()
        if not q:
            return list(self.probes[:limit])
        matches = [
            p
            for p in self.probes
            if q in p.name.lower()
            or q in p.source.lower()
            or q in p.category.lower()
            or q in p.root_cause.lower()
        ]
        return matches[:limit]

    def scan_source(self, script_path: str, source: str, limit: int = 25) -> list[Finding]:
        """Runs all 120 precompiled Luau debugger probes against a script."""
        findings: list[Finding] = []
        for probe in self.probes:
            if probe.pattern.search(source):
                findings.append(
                    Finding(
                        severity=probe.severity,
                        category=f"LuauPack:{probe.category}",
                        title=f"[{probe.id}] {probe.name} ({probe.source})",
                        path=script_path,
                        flaw=probe.root_cause,
                        abuse=f"Detected by {probe.source} diagnostic '{probe.name}'.",
                        fix=probe.fix,
                        metadata={"pack_id": probe.id, "source": probe.source},
                    )
                )
                if len(findings) >= limit:
                    break
        return findings


def load_debugger_pack(json_path: Path = PACK_JSON_PATH) -> tuple[DebuggerProbe, ...]:
    if not json_path.exists():
        raise FileNotFoundError(f"Luau debugger pack not found: {json_path}")

    raw_items = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(raw_items, list) or len(raw_items) != EXPECTED_PACK_COUNT:
        count = len(raw_items) if isinstance(raw_items, list) else 0
        raise ValueError(f"Expected {EXPECTED_PACK_COUNT} probes in {json_path}, found {count}")

    probes: list[DebuggerProbe] = []
    for item in raw_items:
        probes.append(
            DebuggerProbe(
                id=str(item["id"]),
                source=str(item["source"]),
                category=str(item["category"]),
                severity=str(item["severity"]),
                name=str(item["name"]),
                pattern=re.compile(str(item["pattern"]), re.MULTILINE),
                raw_pattern=str(item["pattern"]),
                root_cause=str(item["root_cause"]),
                fix=str(item["fix"]),
            )
        )
    return tuple(probes)


@lru_cache(maxsize=1)
def get_debugger_pack() -> LuauDebuggerPack:
    """Returns the cached 120-probe Light Luau Debugger Pack."""
    return LuauDebuggerPack(probes=load_debugger_pack())
