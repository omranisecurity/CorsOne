"""Input validation helpers for URLs, domains, and proxy URLs."""

from __future__ import annotations

import json
from urllib.parse import urlparse

import validators


def normalize_url(raw_url: str) -> str:
    """Validate and normalize a target URL."""
    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("Target URL is empty.")
    if validators.url(candidate):
        return candidate
    if validators.domain(candidate):
        return f"https://{candidate}"
    raise ValueError(f"Invalid URL: {raw_url!r}")


def validate_domain(domain: str) -> str:
    """Validate a custom attack domain without a scheme or path."""
    candidate = domain.strip()
    if not candidate:
        raise ValueError("Custom domain cannot be empty.")
    if candidate.startswith(("http://", "https://")):
        raise ValueError("Custom domain should not include a protocol scheme.")
    if "." not in candidate:
        raise ValueError("Custom domain must be a valid hostname, for example 'example.com'.")
    if not validators.domain(candidate):
        raise ValueError(f"Invalid domain format: {domain!r}")
    return candidate


def parse_header_json(raw_headers: str) -> dict[str, str]:
    """Parse a JSON header map or raise a clear ValueError."""
    try:
        parsed = json.loads(raw_headers)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Custom headers must be valid JSON, for example '{\"Cookie\": \"value\"}'."
        ) from exc

    if not isinstance(parsed, dict):
        raise ValueError("Custom headers must be a JSON object mapping header names to values.")

    cleaned: dict[str, str] = {}
    for key, value in parsed.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("Custom header names and values must be strings.")
        cleaned[key] = value
    return cleaned


def validate_proxy_url(proxy_url: str) -> str:
    """Validate proxy configuration and reject unsupported SOCKS URLs."""
    candidate = proxy_url.strip()
    if not candidate:
        raise ValueError("Proxy URL cannot be empty.")
    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(
            "Unsupported proxy scheme. Only http:// and https:// proxies are supported; "
            "SOCKS proxies require explicit integration and are intentionally rejected."
        )
    if not parsed.hostname:
        raise ValueError(f"Invalid proxy URL: {proxy_url!r}")
    return candidate


__all__ = [
    "normalize_url",
    "validate_domain",
    "parse_header_json",
    "validate_proxy_url",
]
