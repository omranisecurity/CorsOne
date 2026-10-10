# CorsOne

CorsOne is a Python command-line tool that sends a set of crafted `Origin` headers to a web endpoint and inspects the CORS response headers. It is intended for developers and security testers assessing systems they own or are authorized to test.

CorsOne provides candidate indicators, not proof that sensitive data can be read by an attacker. Review the response evidence and confirm any finding in an authorized browser-based test.

## Features

- Scan one URL, a file of URLs, or URLs piped through standard input.
- Send 51 distinct `Origin` test values per target by default.
- Use `GET` or `POST`, custom headers, and HTTP/HTTPS proxies.
- Export plain text, JSON, or SARIF-shaped reports.
- Run as an installed `corsone` command, with `python -m corsone`, or through the legacy `CorsOne.py` launcher.

## Requirements

- Python 3.10 through 3.14.
- Runtime dependencies are installed automatically from the project metadata.
- CI runs on Ubuntu; Windows has also been used for local development. macOS is not covered by the configured CI workflow.

## Install from source

```powershell
git clone https://github.com/omranisecurity/CorsOne.git
cd CorsOne
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

For development, install the test and quality tools as well:

```powershell
python -m pip install -e ".[dev]"
```

See the [CorsOne Wiki](https://github.com/omranisecurity/CorsOne/wiki) for alternative shell commands, full installation details, and the complete CLI reference.

## Quick start

Start a local web application you control, then scan one of its endpoints:

```console
corsone --url https://target.com/ --silent
```

Replace the URL with an endpoint you own or are explicitly authorized to assess. CorsOne prints one `SAFE` or `VULNERABLE` line per test value. A `VULNERABLE` label is a candidate signal and requires manual validation.

Example output shape (illustrative only):

```text
SAFE Reflected Origin: https://attacker.com
```

## Common examples

Scan multiple authorized targets from a file:

```console
corsone --list targets.txt --silent
```

Send a custom header and save JSON output:

```console
corsone --url https://app.example.test/api \
  --headers '{"X-Test": "assessment"}' \
  --format json --output report.json --silent
```

The `app.example.test` hostname is an example placeholder; use only an authorized target. More examples and option details are in the [Wiki](https://github.com/omranisecurity/CorsOne/wiki).

## Documentation

The [CorsOne Wiki](https://github.com/omranisecurity/CorsOne/wiki) covers installation, usage, all CLI options, scan behavior, result interpretation, output formats, troubleshooting, and development.

## Security and responsible use

Only scan systems you own or have explicit permission to test. Scans send multiple HTTP requests and can affect target systems; use appropriate rate limits and coordinate with system owners. Keep custom headers and report files free of unnecessary secrets.

See [SECURITY.md](SECURITY.md) for reporting security issues.

## Contributing

Bug reports and focused contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development and validation steps.

## License

CorsOne is licensed under the [MIT License](LICENSE).
