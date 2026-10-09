"""Command-line interface for CorsOne."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import build_scan_config
from .reporting import render_json_report, render_sarif_report, render_text_report
from .scanner import CORSVulnerabilityScanner
from .validators import normalize_url

logger = logging.getLogger("corsone.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corsone",
        description="Detect cross-origin resource sharing (CORS) misconfigurations.",
        epilog=f"CorsOne {__version__} | https://github.com/omranisecurity/CorsOne",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("-u", "--url", help="Target URL to scan")
    input_group.add_argument("-l", "--list", help="File containing one target URL per line")
    parser.add_argument(
        "-m",
        "--method",
        choices=["GET", "POST"],
        default="GET",
        help="HTTP method to use for the Origin challenge",
    )
    parser.add_argument(
        "-sof",
        "--stop-on-first",
        action="store_true",
        help="Stop after the first vulnerable result is found",
    )
    parser.add_argument(
        "-cd",
        "--custom-domain",
        default="attacker.com",
        help="Custom attacker domain used in bypass payloads",
    )
    parser.add_argument(
        "-H",
        "--headers",
        help="JSON object containing custom HTTP headers, for example '{\"Cookie\": \"value\"}'",
    )
    parser.add_argument(
        "-p",
        "--proxy",
        help="HTTP/HTTPS proxy URL such as https://proxy.example:8080",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=5,
        help="Number of concurrent workers (default: 5)",
    )
    parser.add_argument(
        "-rl",
        "--rate-limit",
        type=float,
        default=0.0,
        help="Delay between requests in seconds",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=3,
        help="Retry count for failed requests",
    )
    parser.add_argument("-o", "--output", help="Output file path for results")
    parser.add_argument(
        "-f",
        "--format",
        choices=["txt", "json", "sarif"],
        default="txt",
        help="Output format",
    )
    parser.add_argument("--log", help="Optional log file path")
    parser.add_argument(
        "-vo",
        "--vuln-only",
        action="store_true",
        help="Only output vulnerable findings",
    )
    parser.add_argument(
        "-nc",
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument("-s", "--silent", action="store_true", help="Do not print the banner")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the installed CorsOne version",
    )
    return parser


def _read_target_urls(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    if args.url:
        return [normalize_url(args.url)]
    if args.list:
        try:
            with open(args.list, encoding="utf-8") as handle:
                return [normalize_url(line.strip()) for line in handle if line.strip()]
        except OSError as exc:
            parser.error(f"Failed to read URL list: {exc}")
    if not sys.stdin.isatty():
        return [normalize_url(line.strip()) for line in sys.stdin if line.strip()]
    parser.error("No target URL(s) supplied. Use --url, --list, or pipe input.")
    return []


def _write_output(payload: str, path: str | None) -> None:
    if path:
        output_root = Path.cwd().resolve()
        output_path = (output_root / path).resolve()
        try:
            output_path.relative_to(output_root)
        except ValueError as exc:
            raise ValueError(
                "Output path must refer to a file inside the current working directory."
            ) from exc
        output_path.write_text(payload, encoding="utf-8")
        return
    print(payload)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"CorsOne {__version__}")
        return 0

    try:
        urls = _read_target_urls(args, parser)
        config = build_scan_config(args)
        config.url = urls[0] if urls else ""
    except ValueError as exc:
        parser.error(str(exc))

    if not args.silent:
        print(
            f"""
┌──────────────────────────────────────────────────────┐
│                        CorsOne                       │
│         CORS misconfiguration discovery tool         │
│      v{__version__} | github.com/omranisecurity/CorsOne      │
└──────────────────────────────────────────────────────┘
""".strip()
)

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    scanner = CORSVulnerabilityScanner(config)
    results, _ = scanner.scan(urls)

    if config.output_format == "txt":
        payload = render_text_report(results, vulnerable_only=config.vulnerable_only)
    elif config.output_format == "json":
        payload = render_json_report(results, vulnerable_only=config.vulnerable_only)
    else:
        payload = render_sarif_report(results, vulnerable_only=config.vulnerable_only)

    try:
        _write_output(payload, config.output_file)
    except (OSError, ValueError) as exc:
        parser.error(f"Failed to write output: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
