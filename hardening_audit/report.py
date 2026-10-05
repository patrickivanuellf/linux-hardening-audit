"""Scoring and report rendering."""
from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import __version__
from .checks import FAIL, PASS, SKIP, WARN, WEIGHTS, Result

_COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", SKIP: "\033[90m"}
_RESET = "\033[0m"


def score(results: List[Result]) -> int:
    """0-100. PASS earns full weight, WARN half, FAIL none. SKIP is ignored."""
    total = earned = 0.0
    for r in results:
        if r.status == SKIP:
            continue
        weight = WEIGHTS[r.severity]
        total += weight
        if r.status == PASS:
            earned += weight
        elif r.status == WARN:
            earned += weight / 2
    return round(100 * earned / total) if total else 0


def summary(results: List[Result]) -> Dict[str, int]:
    counts = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
    for r in results:
        counts[r.status] += 1
    return counts


def _group(results: List[Result]) -> "OrderedDict[str, List[Result]]":
    grouped: "OrderedDict[str, List[Result]]" = OrderedDict()
    for r in results:
        grouped.setdefault(r.category, []).append(r)
    return grouped


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def render_text(results: List[Result], target: str, color: bool = False,
                generated_at: Optional[str] = None) -> str:
    def paint(status: str) -> str:
        label = f"{status:<4}"
        return f"{_COLORS[status]}{label}{_RESET}" if color else label

    lines = [f"Linux Hardening Audit v{__version__}",
             f"Target:    {target}",
             f"Generated: {generated_at or _now()}", ""]
    for category, items in _group(results).items():
        lines.append(f"[{category}]")
        for r in items:
            lines.append(f"  {paint(r.status)}  {r.id:<8} {r.title}")
            if r.status != PASS and r.detail:
                lines.append(f"            {r.detail}")
            if r.status in (FAIL, WARN) and r.fix:
                lines.append(f"            fix: {r.fix}")
        lines.append("")
    s = summary(results)
    lines.append(f"Summary: {s[PASS]} passed, {s[WARN]} warnings, "
                 f"{s[FAIL]} failed, {s[SKIP]} skipped")
    lines.append(f"Score:   {score(results)}/100")
    return "\n".join(lines) + "\n"


def render_json(results: List[Result], target: str,
                generated_at: Optional[str] = None) -> str:
    payload = {
        "tool": "linux-hardening-audit",
        "version": __version__,
        "target": target,
        "generated_at": generated_at or _now(),
        "score": score(results),
        "summary": summary(results),
        "results": [asdict(r) for r in results],
    }
    return json.dumps(payload, indent=2) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(results: List[Result], target: str,
                    generated_at: Optional[str] = None) -> str:
    s = summary(results)
    lines = ["# Linux Hardening Audit Report", "",
             f"- **Target:** `{target}`",
             f"- **Generated:** {generated_at or _now()}",
             f"- **Score:** {score(results)}/100 "
             f"({s[PASS]} passed, {s[WARN]} warnings, {s[FAIL]} failed, {s[SKIP]} skipped)",
             ""]
    for category, items in _group(results).items():
        lines += [f"## {category}", "", "| Status | ID | Check | Detail |", "|---|---|---|---|"]
        for r in items:
            lines.append(f"| {r.status} | {r.id} | {_cell(r.title)} | {_cell(r.detail)} |")
        lines.append("")
    todo = [r for r in results if r.status in (FAIL, WARN) and r.fix]
    if todo:
        lines += ["## Recommendations", ""]
        for i, r in enumerate(todo, 1):
            lines.append(f"{i}. **{r.id}** ({r.status}) {r.title}: `{_cell(r.fix)}`")
        lines.append("")
    return "\n".join(lines)
