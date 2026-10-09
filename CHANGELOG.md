# Changelog

## 2.0.0

### Breaking changes

- TLS certificate verification is now enabled by default. Use `--insecure` only for testing endpoints with invalid certificates.
- Replaced `-ch`/`--custom-headers` with `-H`/`--headers` for custom headers.
- Output files now use the exact path supplied with `--output` instead of changing its extension to match the format.

### Added and fixed

- Added SARIF report generation and support for multiple output formats.
- Fixed scan state so repeated scans on the same scanner instance are isolated.
- Corrected custom-domain examples in the README.

## 1.1.0

- Refactored logging for clearer runtime information and debugging.
- Reworked the scanner to use asynchronous HTTP requests with `aiohttp` and removed the `requests` dependency.
- Refactored custom-domain CLI options and updated their documentation.
- Included general cleanup and internal optimizations.
- Modernized the project into a `src/` package layout.
- Added a clean CLI, validated configuration, and structured reporting.
- Added automated pytest coverage for validation, payload generation, and scanner behavior.
- Kept a backwards-compatible `CorsOne.py` launcher.

## 1.0.0-beta (pre-release)

- Expanded test coverage and CORS misconfiguration test cases.
- Improved scanning performance and request handling for large target lists.
- Reduced false positives through improved validation logic.
- Improved the codebase for maintainability and future development.

## 0.9.8

- Updated dependencies.
- Fixed the null-origin test case (related to issue #3).

## 0.9.6

- Updated test cases based on recent community research.

## 0.9.5

- Added early exit after the first detected vulnerability.
- Improved scanning performance.
- Simplified the codebase by removing proxy functionality.

## 0.9.4 (pre-release)

- Added scanning multiple URLs from a list.
- Added request rate limiting.
- Added an option to choose the HTTP request method.
- Added SOCKS4/SOCKS5 support and proxy-list options.

## 0.9.0 (pre-release)

- Initial CorsOne pre-release.
