"""Configuration-building helpers."""

from __future__ import annotations

import argparse
from pathlib import Path

from .models import ScanConfig
from .validators import (
    normalize_url,
    parse_header_json,
    validate_domain,
    validate_proxy_url,
)


def infer_output_format(path: str | None, explicit_format: str) -> str:
    """Infer the output format from a path when the format is not explicit."""
    if explicit_format:
        return explicit_format
    if not path:
        return "txt"
    suffix = Path(path).suffix.lower().lstrip(".")
    if suffix in {"json", "txt", "sarif"}:
        return suffix
    return "txt"


def build_scan_config(args: argparse.Namespace) -> ScanConfig:
    """Translate CLI arguments into a validated configuration object."""
    custom_headers = None
    if args.headers:
        custom_headers = parse_header_json(args.headers)

    url_value = getattr(args, "url", None)
    target_url = normalize_url(url_value) if url_value else None

    proxy_value = None
    if args.proxy:
        proxy_value = validate_proxy_url(args.proxy)

    output_format = infer_output_format(args.output, args.format)

    if args.custom_domain:
        custom_domain = validate_domain(args.custom_domain)
    else:
        custom_domain = "attacker.com"

    return ScanConfig(
        url=target_url or "",
        method=args.method,
        custom_domain=custom_domain,
        rate_limit=float(args.rate_limit),
        timeout=int(args.timeout),
        retries=int(args.retries),
        backoff_factor=float(getattr(args, "backoff_factor", 0.5)),
        max_workers=int(args.workers),
        stop_on_first=bool(args.stop_on_first),
        no_color=bool(args.no_color),
        output_file=args.output,
        output_format=output_format,
        output_log=args.log,
        custom_headers=custom_headers,
        proxy=proxy_value,
        verbose=bool(args.verbose),
        vulnerable_only=bool(args.vuln_only),
        verify_ssl=not bool(args.insecure),
    )


__all__ = ["build_scan_config", "infer_output_format"]
