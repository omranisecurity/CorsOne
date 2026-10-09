"""SARIF report rendering."""

from __future__ import annotations

import json
from collections.abc import Iterable

from .. import __version__
from ..models import ScanResult


def render_sarif_report(results: Iterable[ScanResult], *, vulnerable_only: bool = False) -> str:
    sarif_results = []
    for result in results:
        if vulnerable_only and not result.is_vulnerable:
            continue
        rule_level = "warning" if result.is_vulnerable else "note"
        message = (
            f"CORS misconfiguration detected via {result.bypass_name}"
            if result.is_vulnerable
            else f"No CORS misconfiguration found for {result.bypass_name}"
        )
        sarif_results.append(
            {
                "ruleId": "cors-bypass",
                "level": rule_level,
                "message": {"text": message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": result.url}}}],
                "properties": {
                    "bypass_name": result.bypass_name,
                    "bypass_value": result.bypass_value,
                    "response_code": result.response_code,
                    "access_control_allow_credentials": result.acac,
                    "access_control_allow_origin": result.acao,
                    "vulnerability_type": "CORS",
                },
            }
        )

    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CorsOne",
                        "version": __version__,
                        "informationUri": "https://github.com/omranisecurity/CorsOne",
                        "rules": [
                            {
                                "id": "cors-bypass",
                                "name": "CORS misconfiguration",
                                "shortDescription": {
                                    "text": "CORS misconfiguration discovered in a target endpoint."
                                },
                                "fullDescription": {
                                    "text": (
                                        "Tests for credentialed cross-origin access that "
                                        "is enabled via CORS."
                                    )
                                },
                                "defaultConfiguration": {"level": "warning"},
                                "properties": {"tags": ["security", "cors"]},
                            }
                        ],
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(report, indent=2)
