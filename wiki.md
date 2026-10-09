# CorsOne Wiki

This guide documents CorsOne as implemented in version 2.0.0. The code and `pyproject.toml` are the source of truth; options mentioned in older documentation may not be implemented.

## Contents

- [Introduction](#introduction)
- [How CorsOne works](#how-corsone-works)
- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Usage examples](#usage-examples)
- [Configuration](#configuration)
- [Understanding scan results](#understanding-scan-results)
- [Output formats and integration](#output-formats-and-integration)
- [Security, privacy, and safe operation](#security-privacy-and-safe-operation)
- [Troubleshooting](#troubleshooting)
- [Development and testing](#development-and-testing)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)
- [Frequently asked questions](#frequently-asked-questions)
- [Contributing and security reporting](#contributing-and-security-reporting)
- [Version and release information](#version-and-release-information)
- [License and acknowledgments](#license-and-acknowledgments)

## Introduction

CorsOne is a Python command-line utility for sending CORS-related `Origin` header test cases to HTTP endpoints and recording the response headers. It is intended for developers and security testers evaluating systems they own or are explicitly authorized to assess.

CorsOne can help identify responses that merit further investigation. It does not emulate a victim's browser or establish that victim-specific authenticated content can be read cross-origin. If custom credentials are supplied as headers, CorsOne sends those headers as configured.

## How CorsOne works

1. A target is supplied as a URL, a line in a target file, or a line on standard input. A bare domain is normalized to an HTTPS URL.
2. CorsOne extracts the target's network location to construct payloads, then sends requests to the target URL. It uses the selected `GET` or `POST` method, sends no request body, does not follow redirects, and sets one generated value in the `Origin` request header.
3. The payload generator currently returns 51 distinct values. They cover reflected and `null` origins; target-like, subdomain, scheme, and suffix cases; numbered hostname/punctuation variants; and values intended to probe permissive regular-expression rules. Several candidates deliberately contain characters or forms that a browser would not normally serialize as an origin.
4. CorsOne reads `Access-Control-Allow-Credentials` and `Access-Control-Allow-Origin` from the response. It labels a response vulnerable when credentials are `true` (case-insensitive) and the allow-origin value is either exactly the submitted test value **or exactly the target URL's scheme and authority**.
5. Results are rendered as text, JSON, or a SARIF 2.1.0-shaped document.

The target-origin alternative in step 4 is broader than matching the submitted attacker origin. Therefore, a `VULNERABLE` result can be a false positive: verify that the response actually authorizes the tested origin before treating it as an exploitable cross-origin vulnerability. Conversely, a negative scan does not establish that all CORS configurations or browser behaviors are safe.

### Payload count

The generator contains 51 dictionary entries with 51 unique values. This is the number of test requests per target when all checks run; `--stop-on-first` can reduce the number of requests. The payloads are generated from the target's network location and the configured custom domain. They are test inputs, not a guarantee of complete CORS coverage.

## Requirements and installation

### Requirements

- Python `>=3.10,<3.15` (Python 3.10 through 3.14).
- Runtime dependencies declared in `pyproject.toml`:
  - `aiohttp`
  - `aiodns`
  - `validators`
  - `colorama`
- The project metadata does not restrict supported operating systems. The configured GitHub Actions workflow runs on Ubuntu; Windows is used for local development in this repository. macOS is not included in the configured CI matrix.

### Install from the Git repository

Windows PowerShell:

```powershell
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
```

For an editable install suitable for development, replace the final command with:

```powershell
python -m pip install -e ".[dev]"
```

Linux or macOS shell:

```bash
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Use `python -m pip install -e '.[dev]'` instead when setting up a development environment.

The package metadata defines the `corsone` console command. The repository also supports `python -m corsone`; `CorsOne.py` is a backwards-compatible launcher when running from a source checkout. These instructions install from the repository; they do not assert that a release is published on PyPI.

### Verify installation

```console
corsone --version
python -m corsone --help
```

The version is currently `2.0.0`.

### Uninstall

In the environment where CorsOne was installed:

```console
python -m pip uninstall corsone
```

## Quick start

Start a local test web application that you control and make an endpoint available at `http://127.0.0.1:8000/`. Then run:

```console
corsone --url http://127.0.0.1:8000/ --silent
```

The URL is passed with `--url`; `--silent` omits the startup banner. In the default text format, results look like:

```text
SAFE Reflected Origin: https://attacker.com
```

This is an illustrative output line, not a result from a real target. Use only systems you own or have explicit permission to test.

## CLI reference

The CLI is implemented in `src/corsone/cli.py`. Run `corsone --help` for the installed command's help. Only one target input source can be selected at a time. A target source is not formally required by argparse, but a target URL, target file, or piped input is required to perform a useful scan.

| Option | Required | Type / accepted values | Default | Purpose and validation |
|---|---:|---|---|---|
| `-h`, `--help` | No | Flag | — | Show argparse help and exit. |
| `-u`, `--url URL` | One input source for a single target | URL or domain | None | Scan one target. Full URLs are validated; a valid bare domain is prefixed with `https://`. |
| `-l`, `--list PATH` | One input source for a target list | File path | None | Read one URL/domain per non-empty line. Each line is normalized like `--url`. |
| stdin | One input source for piped targets | One URL/domain per line | Not used when stdin is a terminal | If stdin is not a terminal and neither `--url` nor `--list` is set, read targets from stdin. |
| `-m`, `--method {GET,POST}` | No | `GET` or `POST` | `GET` | HTTP method. POST requests have no configured body. |
| `-sof`, `--stop-on-first` | No | Flag | Off | Test payloads sequentially and stop for each target after the first candidate classified as vulnerable. |
| `-cd`, `--custom-domain DOMAIN` | No | Domain name | `attacker.com` | Set the attacker-domain component used by generated payloads. Validation rejects schemes, paths, empty values, and invalid domains. |
| `-H`, `--headers JSON` | No | JSON object of string keys and string values | None | Add custom request headers. Since custom headers are applied after the generated `Origin` header, a supplied `Origin` key overrides each payload; avoid doing that unless intentional. |
| `-p`, `--proxy URL` | No | HTTP/HTTPS proxy URL | None | Send requests through an HTTP or HTTPS proxy. SOCKS schemes are rejected. |
| `--insecure` | No | Flag | Off; TLS verification enabled | Disable TLS certificate verification. Use only in a controlled test when you understand the risk. |
| `-w`, `--workers N` | No | Positive integer | `5` | Maximum number of concurrent payload requests per target when not using `--stop-on-first`. |
| `-rl`, `--rate-limit SEC` | No | Non-negative number | `0` | Sleep for this many seconds after each probe. With concurrent workers, each task sleeps after its own response. |
| `-t`, `--timeout SEC` | No | Positive integer | `10` | Total request timeout in seconds. The connection timeout is separately set to 5 seconds. |
| `-r`, `--retries N` | No | Non-negative integer | `3` | Accepted for compatibility, but retries are not implemented; changing this value currently does not change requests. |
| `-o`, `--output PATH` | No | File path | stdout | Write the selected report to a UTF-8 text file. Parent directories are not created automatically. |
| `-f`, `--format {txt,json,sarif}` | No | `txt`, `json`, or `sarif` | `txt` | Select the report format. The format is not inferred from the output filename; specify it explicitly. |
| `--log PATH` | No | File path | None | Accepted by the parser but not currently used to create a log file. |
| `-vo`, `--vuln-only` | No | Flag | Off | Include only results classified as vulnerable in the report. This also excludes request errors because they are not classified as vulnerable. |
| `-nc`, `--no-color` | No | Flag | Off | Accepted for compatibility. Current report output is plain text and does not add color, so this option has no effect. |
| `-s`, `--silent` | No | Flag | Off | Suppress the startup banner. Useful when sending JSON or SARIF to stdout. |
| `-v`, `--verbose` | No | Flag | Off | Enable INFO logging. The scanner currently logs a start message for each target. |
| `--version` | No | Flag | Off | Print the installed package version and exit. |

### Input validation

- Empty or invalid URLs are rejected. A plain valid domain is normalized to HTTPS.
- Target-file blank lines are ignored; invalid non-empty lines stop argument processing with an error.
- Custom headers must be valid JSON representing a string-to-string object.
- Custom domains must be hostnames and must not include a protocol scheme.
- Proxy schemes must be `http` or `https`, and the URL must include a hostname.
- Worker count and timeout must be greater than zero. Retries and rate limit cannot be negative.

## Usage examples

Scan one authorized endpoint:

```console
corsone --url https://app.example.test/api --silent
```

Scan a file of authorized targets:

```console
corsone --list targets.txt --workers 3 --rate-limit 0.2 --silent
```

Pipe targets from another command:

```console
type targets.txt | corsone --silent
```

On Linux/macOS, the corresponding shell form is:

```bash
cat targets.txt | corsone --silent
```

Use POST, with no request body:

```console
corsone --url https://app.example.test/api --method POST --silent
```

Add custom headers:

```console
corsone --url https://app.example.test/api --headers '{"X-Assessment": "authorized-test"}' --silent
```

Do not put credentials in examples, source control, or shared shell history. CorsOne does not redact custom header values from the request itself.

Write JSON or SARIF to a file:

```console
corsone --url https://app.example.test/api --format json --output corsone-report.json --silent
corsone --url https://app.example.test/api --format sarif --output corsone-report.sarif --silent
```

Use `--silent` when writing structured output to stdout. Without it, the banner is printed before the report and stdout is not a standalone JSON/SARIF document.

Use a validated HTTP proxy:

```console
corsone --url https://app.example.test/api --proxy http://127.0.0.1:8080 --silent
```

## Configuration

CorsOne currently has no configuration file format and reads no environment variables for its settings. Configure scans through command-line options or the equivalent `ScanConfig` values when using the Python API.

There is no configuration precedence chain: CLI arguments are parsed and used to build the scan configuration. `--url`, `--list`, and stdin are mutually exclusive target sources.

`--log`, `--retries`, and `--no-color` are accepted CLI options but currently have no operational effect. See the [Known limitations](#known-limitations) section.

## Understanding scan results

### Result fields

The `ScanResult` model contains:

| Field | Meaning |
|---|---|
| `url` | Target URL that was requested. |
| `bypass_name` | Label for the generated test case. |
| `bypass_value` | The value used for that test's `Origin` header. |
| `is_vulnerable` | Boolean set by the scanner's current response-header rule. |
| `response_code` | HTTP status code; defaults to `0` if a request error occurred before a response. |
| `acac` | `Access-Control-Allow-Credentials` response header, or null/omitted when absent. |
| `acao` | `Access-Control-Allow-Origin` response header, or null/omitted when absent. |
| `error` | Timeout or aiohttp client error text when such an error was caught. |
| `timestamp` | Unix timestamp in seconds when the result object was created. |

### Classification and evidence

The current implementation sets `is_vulnerable` only when:

1. `Access-Control-Allow-Credentials` is present and its value equals `true`, ignoring case; and
2. `Access-Control-Allow-Origin` exactly equals either the submitted payload or the target's scheme and authority.

This is an implementation rule, not a browser exploitability proof. In particular, a response allowing the target's own origin does not by itself demonstrate that it allows the tested cross-origin origin. Treat the matching payload and response headers as evidence to inspect, not a final security conclusion.

The scanner does not validate whether the endpoint returns sensitive data, whether a victim browser can reach it with credentials, or whether other browser controls affect access. To validate a candidate, use a controlled test account and a page served from a different origin than the target, then make a credentialed browser request to the target endpoint and confirm whether the response body is readable by that page. For example, in that controlled page's developer console:

```javascript
fetch("https://app.example.test/api", { credentials: "include" })
  .then((response) => response.text())
  .then((body) => console.log(body));
```

Replace the example endpoint with an authorized test endpoint. A successful network response alone is not enough; the key question is whether browser JavaScript on the separate origin can read the response.

### Errors and negative results

The scanner catches asyncio timeouts and aiohttp client errors and creates a result with `response_code` 0 and an `error` field. Such results have `is_vulnerable=False`. Text output therefore labels an error as `SAFE`; SARIF likewise records it as a note, while JSON can include the error text. A `SAFE` line can mean “no matching headers” or “request failed”; inspect JSON for error details or rerun with verbose logging.

A scan with no vulnerable results is not proof of safety. Coverage is limited to the generated values, supplied target path/method, the observed response, and the implementation's classification rule.

## Output formats and integration

Use `--format txt`, `--format json`, or `--format sarif`. The default is text. Save to a file with `--output PATH`, or omit `--output` to write the report to stdout.

### Plain text

One line is rendered for each included result:

```text
SAFE Reflected Origin: https://attacker.com
```

The text format does not include HTTP status, response headers, timestamps, or error detail.

### JSON

JSON output is a top-level array of serialized `ScanResult` objects. Fields whose value is `None` are omitted. A representative response-backed result is:

```json
[
  {
    "url": "https://app.example.test/api",
    "bypass_name": "Reflected Origin",
    "bypass_value": "https://attacker.com",
    "is_vulnerable": false,
    "response_code": 200,
    "timestamp": 1791571200.0
  }
]
```

In actual output, `acac` and `acao` are omitted if null. The timestamp above is illustrative. Error results include `error` and use a response code of `0`.

Parse a saved report with Python:

```python
import json

with open("corsone-report.json", encoding="utf-8") as report_file:
    results = json.load(report_file)
```

### SARIF

SARIF output is a JSON document declaring version `2.1.0`, with one driver rule (`cors-bypass`) and a result per included scan result. The result level is `warning` for candidates and `note` for other results. CorsOne emits a SARIF-shaped report; the project does not currently include a schema-validation test, so validate it with your consuming security tool before relying on it in a pipeline.

For stdout integration, pass `--silent` so the startup banner does not precede the JSON/SARIF document. When `--output` is used, the report is written to the requested file and the banner remains on stdout unless silenced.

## Security, privacy, and safe operation

- Obtain explicit authorization and agree on scope before scanning.
- A default full scan sends 51 requests per target. Use `--stop-on-first`, `--workers`, and `--rate-limit` with care; rate limiting and concurrency can affect the request rate but do not guarantee a safe production impact.
- The scanner does not follow redirects. Redirect behavior and endpoint-specific routing may therefore affect observed results.
- TLS certificate verification is enabled by default. `--insecure` disables verification and should be limited to controlled testing; it is not a general solution to connectivity problems.
- Custom headers may contain credentials and are sent to the target. Avoid storing secrets in commands or reports. A custom `Origin` header overrides generated payloads and can invalidate the test.
- Output can expose target URLs, response metadata, or errors. Protect report files and remove sensitive files when no longer needed.
- HTTP status alone does not determine the finding classification. The scanner evaluates CORS response headers even for non-success statuses.
- The scanner sends GET/POST requests only; POST has no body. Do not assume the request is harmless for a state-changing endpoint.

See [SECURITY.md](SECURITY.md) for the repository's private vulnerability-reporting guidance.

## Troubleshooting

| Symptom | Likely cause | Recommended action |
|---|---|---|
| `No target URL(s) supplied...` | No URL, list, or piped input was provided while stdin is a terminal. | Supply `--url`, `--list`, or pipe one or more targets. |
| `Invalid URL` | The value is neither accepted as a URL nor a valid domain. | Include a valid hostname and, when needed, a scheme such as `https://`. |
| Target-list read error | The path does not exist or is not readable. | Check the path, permissions, and file encoding; save one target per line. |
| Custom headers validation error | The value is not a JSON object containing only string keys and string values. | Quote a JSON object, for example `'{"X-Test":"value"}'`; shell quoting differs between terminals. |
| Unsupported proxy scheme | The proxy is not HTTP or HTTPS (for example, SOCKS). | Use a supported HTTP/HTTPS proxy; SOCKS is not implemented. |
| Request times out | The target is slow, unreachable, or the selected timeout is too short. | Confirm the target is reachable and adjust `--timeout`; avoid raising load by blindly increasing workers. |
| TLS or connection error | Certificate validation, DNS, network, proxy, or server connectivity may be involved. | Check the endpoint and proxy configuration. Keep TLS verification enabled unless testing a controlled certificate scenario. |
| A result says `SAFE` but the request failed | Text reports classify any non-vulnerable result as SAFE, including caught request errors. | Inspect JSON for `error` and `response_code: 0`; use `--verbose` for target-level scan-start logs. |
| JSON/SARIF printed to stdout cannot be parsed | The startup banner was printed before the report. | Add `--silent`, or write the report to a file with `--output`. |
| Output-file write fails | The destination directory is missing or access is denied. | Choose a writable path; CorsOne does not create parent directories. |
| `--retries`, `--log`, or `--no-color` appears ineffective | These arguments are accepted but are not wired to active behavior. | Do not rely on them; retries, log-file output, and colored output are not currently implemented. |

Exact network error text depends on Python, aiohttp, and the operating system.

## Development and testing

From a clone, create and activate a virtual environment, then install the development extras:

```console
python -m venv .venv
```

Windows PowerShell activation:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Linux/macOS activation:

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run checks from the repository root:

```console
pytest
ruff check .
mypy src
```

The development extra includes the `build` frontend used by CI. After installing `.[dev]`, build a distribution with:

```console
python -m build
```

If you are not using the development extra, install the build frontend separately with `python -m pip install build`.

The CI workflow runs on Ubuntu with Python 3.10, 3.12, and 3.14. It installs development extras, runs Ruff, mypy, pytest with coverage, builds the distribution, and runs `pip-audit`.

## Project structure

```text
.
├── CorsOne.py                 # Backwards-compatible source-checkout launcher
├── pyproject.toml             # Package metadata, dependencies, CLI entry point, tool config
├── src/
│   └── corsone/
│       ├── __init__.py        # Package version
│       ├── __main__.py        # python -m corsone entry point
│       ├── cli.py             # Argument parser and CLI orchestration
│       ├── config.py          # CLI-to-scan configuration
│       ├── models.py          # ScanConfig and ScanResult
│       ├── payloads.py        # Origin test-value generation
│       ├── scanner.py         # Async HTTP scanning
│       ├── validators.py      # URL, domain, headers, and proxy validation
│       └── reporting/         # Text, JSON, and SARIF-shaped output
├── tests/
│   ├── unit/
│   └── integration/
├── .github/workflows/         # CI and code-scanning workflows
├── README.md
├── wiki.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
└── LICENSE
```

## Known limitations

- The finding rule accepts either the submitted origin or the target's own scheme and authority in `Access-Control-Allow-Origin`; the latter may produce false positives for cross-origin access. Manual validation is required.
- The scanner sends a finite set of 51 generated header values. It is not an exhaustive CORS audit.
- Some payloads are intentionally malformed or browser-noncanonical probes; a response to them is not necessarily evidence of a browser-usable origin.
- Request errors are stored as non-vulnerable results and can appear as `SAFE` in text output.
- `--retries` is parsed and validated but has no effect; no retry loop is implemented.
- `--log` is parsed but does not create a log file.
- `--no-color` is parsed but current report output is already uncolored.
- A custom `Origin` header overrides the generated payload.
- The CLI accepts GET and POST only, and POST sends no body.
- Redirects are not followed.
- The configured CI workflow does not test macOS.
- The report implementation does not currently have tests that validate JSON/SARIF schemas or every report edge case.

These are current implementation limitations, not claims about planned features.

## Frequently asked questions

### What does CorsOne detect?

It looks for responses that combine `Access-Control-Allow-Credentials: true` with a matching `Access-Control-Allow-Origin` value according to the current implementation rule. See [How CorsOne works](#how-corsone-works).

### Does `VULNERABLE` always mean the target is exploitable?

No. It is a candidate classification based on response headers. The target-origin matching alternative can produce false positives, and CorsOne does not verify browser access to sensitive data.

### Can I scan production systems?

Only with explicit authorization and an agreed scope. A full scan sends 51 requests per target by default; assess the impact and coordinate rate limits before scanning.

### Does `SAFE` prove the target is safe?

No. It means the current test did not produce a response classified as vulnerable. It may also mask a caught request error in text output. It does not cover all possible origins, browser behaviors, endpoints, or application states.

### How do I check the installed version?

Run `corsone --version` or `python -m corsone --version`.

### How can I report a bug or request a feature?

Use the repository's [GitHub Issues](https://github.com/omranisecurity/CorsOne/issues) page for reproducible bugs and feature requests. Do not post vulnerability details publicly; follow [SECURITY.md](SECURITY.md) for private security reporting.

## Contributing and security reporting

Contributions should be focused and include tests for behavior changes. Follow [CONTRIBUTING.md](CONTRIBUTING.md) to set up development dependencies and run checks. For scan logic or payload changes, explain the security impact and add regression tests where practical.

Report vulnerabilities privately using a repository security advisory or the reporting path described in [SECURITY.md](SECURITY.md). Do not disclose details publicly before a fix is available.

## Version and release information

The package version is defined in `src/corsone/__init__.py` and read dynamically by `pyproject.toml`. The current source version is `2.0.0`. Check an installed copy with:

```console
corsone --version
```

The version is currently `2.0.0`; official tagged releases are listed on the [GitHub Releases page](https://github.com/omranisecurity/CorsOne/releases). Check `corsone --version` to see which version is installed. This guide does not imply that a particular package index release exists.

## License and acknowledgments

CorsOne is distributed under the [MIT License](LICENSE). The repository does not currently document additional project-specific acknowledgments.
