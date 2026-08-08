import argparse
import json

import pytest

from netscan.cli import export_json, parse_ports
from netscan.models import ScanResult


def test_export_json_creates_expected_report(tmp_path) -> None:
    output_file = tmp_path / "scan.json"

    export_json(
        file_path=str(output_file),
        target="localhost",
        ip_address="127.0.0.1",
        results=[
            ScanResult(
                port=22,
                is_open=True,
                service="SSH",
                banner="SSH-2.0-OpenSSH_9.6",
            ),
            ScanResult(
                port=80,
                is_open=False,
                service="HTTP",
            ),
            ScanResult(
                port=443,
                is_open=True,
                service="HTTPS",
            ),
        ],
        duration=0.4567,
    )

    with output_file.open(encoding="utf-8") as json_file:
        report = json.load(json_file)

    assert report["target"] == "localhost"
    assert report["ip_address"] == "127.0.0.1"
    assert report["ports_scanned"] == 3
    assert report["open_ports_count"] == 2
    assert report["duration_seconds"] == 0.457

    assert report["open_ports"] == [
        {
            "port": 22,
            "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_9.6",
            "status": "open",
        },
        {
            "port": 443,
            "service": "HTTPS",
            "banner": None,
            "status": "open",
        },
    ]


def test_parse_single_ports() -> None:
    result = parse_ports("22,80,443")

    assert result == [22, 80, 443]


def test_parse_port_range() -> None:
    result = parse_ports("20-25")

    assert result == [20, 21, 22, 23, 24, 25]


def test_parse_mixed_ports_and_ranges() -> None:
    result = parse_ports("22,80,8000-8002")

    assert result == [22, 80, 8000, 8001, 8002]


def test_parse_ports_removes_duplicates() -> None:
    result = parse_ports("80,80,443,443")

    assert result == [80, 443]


def test_parse_ports_sorts_results() -> None:
    result = parse_ports("443,22,80")

    assert result == [22, 80, 443]


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "65536",
        "70000",
        "-1",
    ],
)
def test_parse_ports_rejects_out_of_range_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(value)


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "80-abc",
        "100-20",
        "",
        "80,,443",
    ],
)
def test_parse_ports_rejects_invalid_formats(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(value)
