# Network Scanner

[![CI](https://github.com/adam-bouchiba/network-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/adam-bouchiba/network-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A fast, multithreaded TCP network scanner written in Python for host reconnaissance, service identification, and structured scan reporting.

Built as a cybersecurity engineering project to explore low-level networking, concurrent execution, service enumeration, testing, and secure tooling practices.

---

## Features

- Multithreaded TCP port scanning
- IPv4 and hostname resolution
- Custom ports and port ranges
- Common service identification
- TCP service banner grabbing
- Configurable timeout and worker count
- Optional display of closed ports
- Structured scan results with Python dataclasses
- JSON report export
- Automated unit testing with Pytest
- Static analysis with Ruff
- Type checking with Mypy
- Continuous Integration with GitHub Actions

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/adam-bouchiba/network-scanner.git
cd network-scanner
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

You can now use:

```bash
netscan localhost
```

---

## Usage

Scan the default ports:

```bash
netscan localhost
```

Scan specific ports:

```bash
netscan localhost -p 22,80,443
```

Scan a range:

```bash
netscan localhost -p 1-1000
```

Combine ports and ranges:

```bash
netscan localhost -p 22,80,443,8000-8100
```

Enable banner grabbing:

```bash
netscan localhost -p 22,80,443 --banners
```

Export results to JSON:

```bash
netscan localhost -p 1-1000 --json scan.json
```

Display closed ports:

```bash
netscan localhost -p 20-100 --show-closed
```

Customize concurrency and timeout:

```bash
netscan localhost -p 1-1000 --workers 100 --timeout 0.3
```

View all options:

```bash
netscan --help
```

---

## Example Output

```text
Target:      localhost
Resolved IP: 127.0.0.1
Ports:       7
Workers:     50

Scanning...

PORT      STATUS      SERVICE         BANNER
------------------------------------------------------------------------------
22        CLOSED      SSH             -
80        CLOSED      HTTP            -
135       OPEN        MSRPC           -
443       CLOSED      HTTPS           -
445       OPEN        SMB             -
3389      CLOSED      RDP             -
8080      CLOSED      HTTP-ALT        -

Scan completed in 2.56s with 2 open port(s).
```

Actual results depend on the target and running services.

---

## JSON Reports

Scan results can be exported for further processing:

```json
{
    "target": "localhost",
    "ip_address": "127.0.0.1",
    "duration_seconds": 0.12,
    "ports_scanned": 3,
    "open_ports_count": 1,
    "open_ports": [
        {
            "port": 22,
            "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_9.6",
            "status": "open"
        }
    ]
}
```

This makes scan results easy to integrate with scripts, dashboards, or security workflows.

---

## Architecture

```text
network-scanner/
├── .github/
│   └── workflows/
│       └── ci.yml
├── src/
│   └── netscan/
│       ├── __init__.py
│       ├── cli.py
│       ├── models.py
│       └── scanner.py
├── tests/
│   ├── test_cli.py
│   ├── test_models.py
│   └── test_scanner.py
├── LICENSE
├── pyproject.toml
└── README.md
```

The project separates responsibilities between:

- `scanner.py` — networking and scanning logic
- `models.py` — structured scan result representation
- `cli.py` — command-line interface and report generation
- `tests/` — automated unit tests

---

## Quality & Testing

Run the test suite:

```bash
pytest -v
```

Run static analysis:

```bash
ruff check .
```

Run type checking:

```bash
mypy src tests
```

GitHub Actions automatically runs quality checks and tests on every push and pull request to `main`.

---

## Technical Concepts

This project demonstrates practical use of:

- TCP sockets
- DNS resolution
- Concurrent network operations
- `ThreadPoolExecutor`
- Banner grabbing
- CLI design with `argparse`
- Python dataclasses
- Type hints
- JSON serialization
- Unit testing and mocking
- Continuous Integration

---

## Limitations

This scanner intentionally focuses on TCP reconnaissance and does not currently provide:

- UDP scanning
- OS fingerprinting
- Vulnerability detection
- Advanced service fingerprinting
- SYN / stealth scanning

The goal is to keep the codebase understandable while maintaining a clean foundation for future experimentation.

---

## Responsible Use

This project is intended for educational purposes and authorized security testing.

Only scan systems you own or systems for which you have explicit permission to perform security testing.

---

## License

Distributed under the MIT License. See `LICENSE` for details.