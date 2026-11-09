# TLSGuard

**TLSGuard** is a Python command-line tool for reviewing the TLS configuration exposed by a server. It probes supported TLS protocol versions, tests a curated set of TLS 1.2 cipher suites, inspects the server's leaf X.509 certificate validity dates, and generates security findings with an explainable heuristic score.

> **Project status:** Alpha / educational security-auditing project. Results are intended to support manual review, not replace a professional TLS assessment.

## Features

- Probe TLS 1.0, 1.1, 1.2 and 1.3 individually.
- Distinguish `SUPPORTED`, `NOT_SUPPORTED`, `NOT_TESTABLE` and `ERROR` outcomes instead of treating every failed handshake as proof that a feature is disabled.
- Test a documented selection of TLS 1.2 cipher suites and classify negotiated suites as modern, legacy or weak.
- Retrieve and parse the server's leaf X.509 certificate, including subject, issuer, serial number, SAN DNS names, signature hash and validity dates.
- Detect deprecated TLS versions, weak/legacy negotiated ciphers, and expired, not-yet-valid or soon-to-expire certificates.
- Calculate a transparent risk score when the required checks are complete. Withhold the numeric score when the assessment is incomplete.
- Export machine-readable JSON reports.
- Run automated tests with `pytest`.

## Requirements

- Python 3.12 or newer
- OpenSSL available through Python's `ssl` module
- Network access to the target host and port
- Permission to assess the target system

## Installation (Windows PowerShell)

Clone the repository and enter the project directory:

```powershell
git clone https://github.com/YOUR_USERNAME/tlsguard.git
cd tlsguard
```

Create and activate a virtual environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can use the environment's Python directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Otherwise, install the project and development dependencies with:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Usage

Run a scan against a hostname or IP address. Do not include `https://` or a URL path:

```powershell
python -m tlsguard scan example.com
```

Specify a custom port and per-connection timeout:

```powershell
python -m tlsguard scan example.com --port 443 --timeout 8
```

Export the results to JSON:

```powershell
python -m tlsguard scan example.com --json reports/scan.json
```

Validate the JSON output:

```powershell
python -m json.tool reports/scan.json
```

Display available options:

```powershell
python -m tlsguard --help
python -m tlsguard scan --help
```

After installation, the console entry point is also available:

```powershell
tlsguard scan example.com --json reports/scan.json
```

## Understanding the output

### Probe states

| State | Meaning |
|---|---|
| `SUPPORTED` | The probe completed a handshake using the requested protocol or cipher. |
| `NOT_SUPPORTED` | The remote endpoint explicitly rejected the requested protocol version or no shared cipher was available. |
| `NOT_TESTABLE` | The local TLS implementation or an ambiguous handshake failure prevented a reliable conclusion. |
| `ERROR` | A network, DNS, timeout or other I/O error prevented the probe. |

TLSGuard deliberately avoids interpreting generic handshake failures, timeouts or DNS errors as proof that a protocol or cipher is disabled.

### Security score

The score starts at 100 and subtracts a fixed penalty for each finding:

| Severity | Penalty |
|---|---:|
| Critical | 40 |
| High | 25 |
| Medium | 10 |
| Low | 3 |
| Info | 0 |

The risk bands are `LOW` (90–100), `MEDIUM` (70–89), `HIGH` (40–69) and `CRITICAL` (0–39). These values are an educational prioritization heuristic, not a standardized security rating. TLSGuard withholds the numeric score and reports `INCOMPLETE` if required checks could not be completed. A missing score must not be interpreted as a clean result.

## Exit codes

- `0`: all required checks completed (the resulting risk level may still be `HIGH` or `CRITICAL`).
- `1`: a fatal error occurred, JSON export failed, or the assessment is incomplete. A partial JSON report may still have been written.
- `130`: the user interrupted the scan.

## Run tests

From the repository root:

```powershell
python -m pytest -q
```

Run with verbose test names:

```powershell
python -m pytest -v
```

## Project structure

```text
tlsguard/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── AUDIT_REPORT.md
│   ├── LEARNING_NOTES.md
│   └── METHODOLOGY.md
├── src/
│   └── tlsguard/
│       ├── checks/       # Network probes and certificate parsing
│       ├── models/       # Typed result and finding models
│       ├── rules/        # Security finding rules
│       ├── cli.py        # Command-line interface
│       ├── scanner.py    # Scan orchestration
│       ├── scoring.py    # Heuristic score calculation
│       └── json_report.py
├── tests/                # Automated unit tests
├── pyproject.toml
└── README.md
```

## Scope and limitations

- The cipher check covers the explicit list in `checks/ciphers.py`; it is not a complete enumeration of every cipher a server might support.
- Cipher probing is limited to TLS 1.2. TLS 1.3 cipher suites use a different configuration mechanism and are not currently enumerated by this scanner.
- Certificate inspection retrieves the leaf certificate and evaluates its validity dates. It intentionally does **not** validate the certificate trust chain, revocation status or hostname match. The displayed certificate status therefore describes date validity only, not overall certificate trust.
- Python and the OpenSSL build used by the local machine can restrict which legacy protocols and cipher suites can be tested. TLSGuard reports these cases as `NOT_TESTABLE` where it cannot draw a reliable conclusion.
- The score is a simple weighted sum. Findings are not deduplicated by root cause and the score is not a compliance certification.
- A scan consists of multiple sequential TLS connections. The timeout applies to each socket connection, not to the entire scan. Operating-system DNS resolution happens before the socket connection and may take longer than the configured timeout.

## Responsible use

Only scan systems that you own or are explicitly authorized to assess. TLSGuard is intended for defensive auditing and education. Do not use it to disrupt services or to test third-party systems without permission.

## Development notes

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the code flow, [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for interpretation rules and limitations, and [docs/LEARNING_NOTES.md](docs/LEARNING_NOTES.md) for explanations of the Python networking and TLS APIs used in the project.

## License

MIT. See [LICENSE](LICENSE).
