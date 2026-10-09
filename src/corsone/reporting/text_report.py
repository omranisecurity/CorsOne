"""Plain-text report rendering."""

from __future__ import annotations

from collections.abc import Iterable

from ..models import ScanResult


def render_text_report(results: Iterable[ScanResult], *, vulnerable_only: bool = False) -> str:
    lines: list[str] = []
    for result in results:
        if vulnerable_only and not result.is_vulnerable:
            continue
        status = "VULNERABLE" if result.is_vulnerable else "SAFE"
        lines.append(f"{status} {result.bypass_name}: {result.bypass_value}")
    return "\n".join(lines)
