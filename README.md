# Network Scanner

A fast multithreaded TCP port scanner written in Python.

Network Scanner resolves hostnames, scans configurable TCP port ranges in parallel, identifies common services and displays a clear summary of the results.

> This project was built for educational purposes and authorized security testing.

## Features

- Fast multithreaded TCP port scanning
- IPv4 address and hostname resolution
- Custom port selection
- Port range parsing
- Common service identification
- Configurable connection timeout
- Configurable worker threads
- Optional display of closed ports
- Clear execution summary and scan duration
- Installable command-line interface

## Demo

```text
$ netscan localhost -p 75-85 --show-closed

Target:      localhost
Resolved IP: 127.0.0.1
Ports:       11
Workers:     50

Scanning...

PORT      STATUS      SERVICE
----------------------------------
75        CLOSED      UNKNOWN
76        CLOSED      DEOS
77        CLOSED      PRIV-RJE
78        CLOSED      VETTCP
79        CLOSED      FINGER
80        OPEN        HTTP
81        CLOSED      HOSTS2-NS
82        CLOSED      XFER
83        CLOSED      MIT-ML-DEV
84        CLOSED      CTF
85        CLOSED      MIT-ML-DEV

Scan completed in 0.07s with 1 open port(s).
```

## Requirements

- Python 3.10 or newer
- Git

No external Python dependency is currently required.

## Installation

Clone the repository:

```bash
git clone https://github.com/adam-bouchiba/network-scanner.git
cd network-scanner
```

Create a virtual environment:

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project in editable mode:

```bash
pip install -e .
```

Verify the installation:

```bash
netscan --help
```

## Usage

### Scan the 1,000 default TCP ports

```bash
netscan 127.0.0.1
```

### Scan selected ports

```bash
netscan example.com -p 22,80,443
```

### Scan a port range

```bash
netscan 192.168.1.10 -p 1-1000
```

### Combine individual ports and ranges

```bash
netscan 192.168.1.10 -p 22,80,443,8000-8100
```

### Display closed ports

```bash
netscan localhost -p 75-85 --show-closed
```

### Change the timeout

```bash
netscan localhost -p 1-1000 --timeout 0.3
```

### Change the number of worker threads

```bash
netscan localhost -p 1-1000 --workers 100
```

### Combine options

```bash
netscan localhost -p 1-1000 -t 0.3 -w 100 --show-closed
```

## Command-line options

| Option | Description | Default |
|---|---|---:|
| `target` | IPv4 address or hostname to scan | Required |
| `-p`, `--ports` | Ports or ranges to scan | `1-1000` |
| `-t`, `--timeout` | Connection timeout per port | `0.5` seconds |
| `-w`, `--workers` | Maximum concurrent worker threads | `50` |
| `--show-closed` | Display closed ports | Disabled |

## Project structure

```text
network-scanner/
├── src/
│   └── netscan/
│       ├── __init__.py
│       ├── cli.py
│       └── scanner.py
├── tests/
├── .gitignore
├── pyproject.toml
└── README.md
```

## How it works

For every selected port, the scanner attempts to establish a TCP connection using a Python socket.

A successful connection indicates that the port is open. Failed connection attempts are currently reported as closed.

To improve performance, port scans are distributed across a pool of worker threads using `ThreadPoolExecutor`.

Service names are inferred from common port associations. This is not yet active service fingerprinting.

## Current limitations

- IPv4 only
- TCP connect scanning only
- Closed and filtered states are not yet distinguished
- Service names are inferred from port numbers
- No operating-system detection
- No subnet or CIDR scanning
- No JSON or CSV export yet

## Roadmap

- [x] TCP connect scanning
- [x] Multithreaded port scanning
- [x] Hostname resolution
- [x] Port and range parsing
- [x] Common service identification
- [x] Installable CLI
- [ ] JSON export
- [ ] CSV export
- [ ] Automated tests
- [ ] GitHub Actions continuous integration
- [ ] Banner grabbing
- [ ] CIDR network scanning
- [ ] Structured scan result model
- [ ] Release v1.0.0

## Responsible use

Only scan systems that you own or systems for which you have explicit authorization.

Unauthorized scanning may violate organizational policies or applicable laws. The author is not responsible for misuse of this project.

## Author

**Adam "Cobalt" Bouchiba**

Cybersecurity Engineering Student at ECE Paris.

## License

This project is intended to be released under the MIT License.
