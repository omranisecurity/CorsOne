"""JSON report rendering."""

from __future__ import annotations

import json
from collections.abc import Iterable

from ..models import ScanResult


def render_json_report(results: Iterable[ScanResult], *, vulnerable_only: bool = False) -> str:
    payload = [
        result.to_dict()
        for result in results
        if (not vulnerable_only or result.is_vulnerable)
    ]
    return json.dumps(payload, indent=2)
