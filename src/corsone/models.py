"""Data models used by the scanner and reporting code."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ScanResult:
    """A single Origin payload test result."""

    url: str
    bypass_name: str
    bypass_value: str
    is_vulnerable: bool
    response_code: int = 0
    acac: str | None = None
    acao: str | None = None
    error: str | None = None
    timestamp: float = field(default_factory=lambda: __import__("time").time())

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {key: value for key, value in data.items() if value is not None}

    def summary(self) -> str:
        status = "VULNERABLE" if self.is_vulnerable else "SAFE"
        return f"{status} {self.bypass_name}: {self.bypass_value}"


@dataclass(slots=True)
class ScanConfig:
    """Immutable scan configuration."""

    url: str
    method: str = "GET"
    custom_domain: str = "attacker.com"
    rate_limit: float = 0.0
    timeout: int = 10
    retries: int = 3
    backoff_factor: float = 0.5
    max_workers: int = 5
    stop_on_first: bool = False
    no_color: bool = False
    output_file: str | None = None
    output_format: str = "txt"
    output_log: str | None = None
    custom_headers: dict[str, str] | None = None
    proxy: str | None = None
    verbose: bool = False
    vulnerable_only: bool = False
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        if self.max_workers <= 0:
            raise ValueError("Worker count must be greater than zero.")
        if self.timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")
        if self.retries < 0:
            raise ValueError("Retries cannot be negative.")
        if self.rate_limit < 0:
            raise ValueError("Rate limit cannot be negative.")
        if self.backoff_factor < 0:
            raise ValueError("Backoff factor cannot be negative.")
        if self.method.upper() not in {"GET", "POST"}:
            raise ValueError("Method must be GET or POST.")
        if self.output_format not in {"txt", "json", "sarif"}:
            raise ValueError("Output format must be one of: txt, json, sarif.")


__all__ = ["ScanConfig", "ScanResult"]
